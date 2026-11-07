import Foundation
import CryptoKit

/// Long-lived access keys only. Session tokens / STS credentials are not supported in this version.
/// R2 requires its S3 API endpoint (https://<account>.r2.cloudflarestorage.com), not r2.dev.
struct S3Configuration: Codable, Equatable {
    var endpoint: String = ""
    var bucket: String = ""
    var region: String = "auto"
    var accessKeyID: String = ""
    var secretAccessKey: String = ""
    var prefix: String = ""
}

enum S3Error: LocalizedError {
    case invalidEndpoint
    case invalidBucket
    case invalidRegion
    case invalidPrefix
    case invalidCredentials

    var errorDescription: String? {
        switch self {
        case .invalidEndpoint:
            return "The S3 endpoint must be an HTTPS API origin without a path, credentials, query, or fragment. Use the S3 API endpoint for R2, not r2.dev."
        case .invalidBucket:
            return "Enter a valid existing S3 bucket name. Buckets are not created automatically."
        case .invalidRegion:
            return "The S3 region is invalid. Use auto for Cloudflare R2."
        case .invalidPrefix:
            return "The S3 prefix cannot contain empty path components, . or .., and the complete object key cannot exceed 1024 UTF-8 bytes."
        case .invalidCredentials:
            return "The S3 credentials are invalid. Only long-lived Access Keys without a session token are supported; temporary STS credentials are unsupported."
        }
    }
}

actor S3Client: WebDAVServing {
    private let configuration: S3Configuration
    private let origin: URLComponents
    private let hostHeader: String
    private let sessionConfiguration: URLSessionConfiguration
    private let now: @Sendable () -> Date

    /// Inject protocolClasses on an ephemeral configuration for URLProtocol tests.
    /// A private copy is used, with cache, cookie and credential stores disabled for every request.
    init(configuration: S3Configuration,
         sessionConfiguration: URLSessionConfiguration = .ephemeral,
         now: @escaping @Sendable () -> Date = { Date() }) throws {
        let address = configuration.endpoint
        guard !address.isEmpty,
              !address.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0)
                  || CharacterSet.controlCharacters.contains($0) }),
              !address.contains("\\"),
              var components = URLComponents(string: address),
              components.scheme?.lowercased() == "https",
              let host = components.host?.lowercased(), !host.isEmpty,
              host.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0)
                  || [UInt8(45), 46, 58, 91, 93].contains($0) }),
              host != "r2.dev", !host.hasSuffix(".r2.dev"),
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
              components.port.map({ (1...65535).contains($0) }) ?? true,
              let authorityStart = address.range(of: "://")?.upperBound else {
            throw S3Error.invalidEndpoint
        }
        let authority = address[authorityStart...].prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        guard !authority.contains("%") else { throw S3Error.invalidEndpoint }
        // Foundation may silently drop overflowing ports, so also validate the original bytes.
        if let colon = authority.lastIndex(of: ":"), !authority[colon...].contains("]") {
            let rawPort = authority[authority.index(after: colon)...]
            guard !rawPort.isEmpty, rawPort.utf8.allSatisfy({ (48...57).contains($0) }),
                  let port = Int(rawPort), (1...65535).contains(port) else { throw S3Error.invalidEndpoint }
        }
        guard Self.validBucket(configuration.bucket) else { throw S3Error.invalidBucket }
        guard !configuration.region.isEmpty, configuration.region.utf8.allSatisfy({
            (97...122).contains($0) || (48...57).contains($0) || $0 == 45
        }) else { throw S3Error.invalidRegion }
        let prefix = configuration.prefix
        if !prefix.isEmpty {
            guard prefix.split(separator: "/", omittingEmptySubsequences: false).allSatisfy({
                !$0.isEmpty && $0 != "." && $0 != ".."
            }), prefix.utf8.count + 1 + 51 <= 1024 else { throw S3Error.invalidPrefix }
        }
        guard !configuration.accessKeyID.isEmpty,
              !configuration.accessKeyID.hasPrefix("ASIA"),
              configuration.accessKeyID.utf8.allSatisfy({
                  (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)
              }), !configuration.secretAccessKey.isEmpty,
              configuration.secretAccessKey.utf8.allSatisfy({ (0x21...0x7E).contains($0) }) else {
            throw S3Error.invalidCredentials
        }
        components.scheme = "https"
        components.host = host
        components.percentEncodedPath = ""
        guard components.url != nil else { throw S3Error.invalidEndpoint }
        var authorityHost = host
        if host.contains(":"), !host.hasPrefix("[") { authorityHost = "[" + host + "]" }
        if let port = components.port, port != 443 { authorityHost += ":\(port)" }
        self.configuration = configuration
        origin = components
        hostHeader = authorityHost
        self.sessionConfiguration = sessionConfiguration.copy() as! URLSessionConfiguration
        self.now = now
    }

    /// Read-only ListObjectsV2 probe for the configured key prefix, limited to one result.
    /// Proves listing access only, NOT object read/write permissions. An empty prefix is valid;
    /// no directory markers or probe objects are created, and permission failures are not bypassed.
    func testConnection() async throws {
        let prefix = configuration.prefix.isEmpty ? "" : configuration.prefix + "/"
        let result = try await perform(method: "GET", key: nil,
                                       query: [("prefix", prefix), ("max-keys", "1"), ("list-type", "2")],
                                       maximumBytes: RemoteObjectLimits.errorBody)
        try checkStatus(result.response.statusCode)
        guard result.response.statusCode == 200,
              S3ListDocument.isValid(result.data, bucket: configuration.bucket, prefix: prefix) else {
            throw WebDAVError.invalidResponse
        }
    }

    func download() async throws -> WebDAVDownload? {
        try await downloadObject(name: "vault.enc", maximumBytes: RemoteObjectLimits.vault)
    }

    func downloadAttachment(id: UUID) async throws -> WebDAVDownload? {
        try await downloadObject(name: "attachment-\(id.uuidString).enc", maximumBytes: RemoteObjectLimits.attachment)
    }

    func upload(_ data: Data, expectedETag: String?, createOnly: Bool) async throws -> String? {
        guard data.count <= RemoteObjectLimits.vault else { throw WebDAVError.payloadTooLarge }
        let condition: [String: String]
        if createOnly {
            guard expectedETag == nil else { throw WebDAVError.conflictingConditions }
            condition = ["if-none-match": "*"]
        } else {
            guard let etag = expectedETag, !etag.isEmpty else { throw WebDAVError.missingETag }
            guard WebDAVClient.isStrongETag(etag) else { throw WebDAVError.invalidETag }
            condition = ["if-match": etag]
        }
        return try await uploadObject(data, name: "vault.enc", condition: condition,
                                      maximumBytes: RemoteObjectLimits.vault)
    }

    func uploadAttachment(_ data: Data, id: UUID) async throws -> String? {
        guard data.count <= RemoteObjectLimits.attachment else { throw WebDAVError.payloadTooLarge }
        return try await uploadObject(data, name: "attachment-\(id.uuidString).enc",
                                      condition: ["if-none-match": "*"], maximumBytes: RemoteObjectLimits.attachment)
    }

    private func downloadObject(name: String, maximumBytes: Int) async throws -> WebDAVDownload? {
        let result = try await perform(method: "GET", key: key(name), maximumBytes: maximumBytes)
        // A bare 404, malformed/truncated XML or NoSuchBucket is never an empty vault.
        if result.response.statusCode == 404, !result.errorBodyTruncated,
           S3ErrorDocument.code(in: result.data) == "NoSuchKey" { return nil }
        try checkStatus(result.response.statusCode)
        guard result.response.statusCode == 200 else { throw WebDAVError.invalidResponse }
        return WebDAVDownload(data: result.data, etag: result.response.value(forHTTPHeaderField: "ETag"))
    }

    private func uploadObject(_ data: Data, name: String, condition: [String: String],
                              maximumBytes: Int) async throws -> String? {
        var headers = condition
        headers["content-type"] = "application/octet-stream"
        let result = try await perform(method: "PUT", key: key(name), body: data,
                                       headers: headers, maximumBytes: maximumBytes)
        try checkStatus(result.response.statusCode)
        guard [200, 201, 204].contains(result.response.statusCode) else { throw WebDAVError.invalidResponse }
        return result.response.value(forHTTPHeaderField: "ETag")
    }

    private func key(_ name: String) -> String {
        configuration.prefix.isEmpty ? name : configuration.prefix + "/" + name
    }

    private func perform(method: String, key: String?, query: [(String, String)] = [], body: Data? = nil,
                         headers: [String: String] = [:],
                         maximumBytes: Int = RemoteObjectLimits.vault) async throws -> RemoteResponse {
        try Task.checkCancellation()
        let path = "/" + configuration.bucket + (key.map { "/" + $0 } ?? "")
        let canonicalURI = S3Signer.uriEncode(path, encodeSlash: false)
        let canonicalQuery = S3Signer.canonicalQuery(query)
        var components = origin
        // Set the already-encoded path directly. appendingPathComponent would encode '%' again.
        components.percentEncodedPath = canonicalURI
        components.percentEncodedQuery = canonicalQuery.isEmpty ? nil : canonicalQuery
        guard let url = components.url,
              let wire = URLComponents(url: url, resolvingAgainstBaseURL: false),
              wire.percentEncodedPath == canonicalURI,
              (wire.percentEncodedQuery ?? "") == canonicalQuery else {
            throw S3Error.invalidEndpoint
        }
        let payloadHash = S3Signer.sha256(body ?? Data())
        let date = now()
        var signed = headers
        signed["host"] = hostHeader
        signed["x-amz-date"] = S3Signer.timestamp(date)
        signed["x-amz-content-sha256"] = payloadHash
        let signature = S3Signer.sign(method: method, canonicalURI: canonicalURI,
                                      canonicalQuery: canonicalQuery, headers: signed,
                                      payloadHash: payloadHash, accessKeyID: configuration.accessKeyID,
                                      secretAccessKey: configuration.secretAccessKey,
                                      region: configuration.region, date: date)
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = method
        request.httpBody = body
        for (name, value) in signed { request.setValue(value, forHTTPHeaderField: name) }
        request.setValue(signature.authorization, forHTTPHeaderField: "Authorization")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        return try await RemoteRequest(maximumBytes: maximumBytes, redirectPolicy: .rejectAll,
                                       configuration: sessionConfiguration).run(request)
    }

    private func checkStatus(_ status: Int) throws {
        switch status {
        case 200...299: return
        case 300...399: throw WebDAVError.unsafeRedirect
        case 401: throw WebDAVError.authenticationFailed
        case 403: throw WebDAVError.accessDenied
        case 404: throw WebDAVError.notFound
        case 409: throw WebDAVError.conflict
        case 412: throw WebDAVError.preconditionFailed
        default: throw WebDAVError.httpStatus(status)
        }
    }

    private static func validBucket(_ value: String) -> Bool {
        // Keep DNS-style/path safety, including dotted S3 buckets. Provider-specific reserved
        // names belong to the server: AWS's reserved prefixes/suffixes need not be reserved on R2.
        let bytes = Array(value.utf8)
        func alphanumeric(_ byte: UInt8) -> Bool { (97...122).contains(byte) || (48...57).contains(byte) }
        guard (3...63).contains(bytes.count), let first = bytes.first, let last = bytes.last,
              alphanumeric(first), alphanumeric(last),
              bytes.allSatisfy({ alphanumeric($0) || $0 == 45 || $0 == 46 }),
              !value.contains(".."), !value.contains(".-"), !value.contains("-.") else {
            return false
        }
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        let isIPv4 = parts.count == 4 && parts.allSatisfy {
            !$0.isEmpty && $0.utf8.allSatisfy({ (48...57).contains($0) }) && (Int($0).map { (0...255).contains($0) } ?? false)
        }
        return !isIPv4
    }
}

/// Pure SigV4 building blocks. Inputs are raw UTF-8 strings except canonicalURI / canonicalQuery,
/// which must already be AWS-encoded exactly once. No URI normalization is performed.
enum S3Signer {
    struct Signature {
        let canonicalHeaders: String
        let signedHeaders: String
        let canonicalRequest: String
        let stringToSign: String
        let signature: String
        let authorization: String
    }

    static func uriEncode(_ value: String, encodeSlash: Bool = true) -> String {
        let hex = Array("0123456789ABCDEF".utf8)
        var output = [UInt8]()
        for byte in value.utf8 {
            if (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte)
                || byte == 45 || byte == 46 || byte == 95 || byte == 126 || (!encodeSlash && byte == 47) {
                output.append(byte)
            } else {
                output.append(contentsOf: [37, hex[Int(byte >> 4)], hex[Int(byte & 15)]])
            }
        }
        return String(decoding: output, as: UTF8.self)
    }

    /// Encode raw UTF-8 names/values once, then sort encoded names and encoded values.
    static func canonicalQuery(_ items: [(String, String)]) -> String {
        let encoded: [(name: String, value: String)] = items.map { item in
            (name: uriEncode(item.0), value: uriEncode(item.1))
        }
        let sorted = encoded.sorted { first, second in
            if first.name == second.name { return first.value < second.value }
            return first.name < second.name
        }
        return sorted.map { $0.name + "=" + $0.value }.joined(separator: "&")
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func timestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return formatter.string(from: date)
    }

    static func sign(method: String, canonicalURI: String, canonicalQuery: String = "",
                     headers: [String: String], payloadHash: String, accessKeyID: String,
                     secretAccessKey: String, region: String, date: Date) -> Signature {
        var normalized = [String: String]()
        for (name, value) in headers {
            normalized[name.lowercased()] = value.split(whereSeparator: { $0 == " " || $0 == "\t" }).joined(separator: " ")
        }
        let names = normalized.keys.sorted()
        let canonicalHeaders = names.map { $0 + ":" + normalized[$0]! + "\n" }.joined()
        let signedHeaders = names.joined(separator: ";")
        let canonicalRequest = [method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].joined(separator: "\n")
        let amzDate = timestamp(date)
        let day = String(amzDate.prefix(8))
        let scope = "\(day)/\(region)/s3/aws4_request"
        let stringToSign = "AWS4-HMAC-SHA256\n\(amzDate)\n\(scope)\n\(sha256(Data(canonicalRequest.utf8)))"
        let dateKey = hmac(Data(("AWS4" + secretAccessKey).utf8), day)
        let regionKey = hmac(dateKey, region)
        let serviceKey = hmac(regionKey, "s3")
        let signingKey = hmac(serviceKey, "aws4_request")
        let signature = hmac(signingKey, stringToSign).map { String(format: "%02x", $0) }.joined()
        let authorization = "AWS4-HMAC-SHA256 Credential=\(accessKeyID)/\(scope),SignedHeaders=\(signedHeaders),Signature=\(signature)"
        return Signature(canonicalHeaders: canonicalHeaders, signedHeaders: signedHeaders,
                         canonicalRequest: canonicalRequest, stringToSign: stringToSign,
                         signature: signature, authorization: authorization)
    }

    private static func hmac(_ key: Data, _ value: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: SymmetricKey(data: key)))
    }
}

/// Validate a complete, bounded list response, not just HTTP 200 (which could be a login page).
/// Only listing metadata is inspected; object names are never downloaded or exposed.
private final class S3ListDocument: NSObject, XMLParserDelegate {
    private static let fields: Set<String> = ["Name", "Prefix", "MaxKeys", "KeyCount", "IsTruncated"]
    private var elements = [String]()
    private var values = [String: String]()
    private var contentsCount = 0
    private var valid = true

    static func isValid(_ data: Data, bucket: String, prefix: String) -> Bool {
        guard !data.isEmpty, data.count <= RemoteObjectLimits.errorBody,
              let text = String(data: data, encoding: .utf8), !text.contains("\0"),
              !text.contains("<!DOCTYPE"), !text.contains("<!ENTITY") else { return false }
        let delegate = S3ListDocument()
        let parser = XMLParser(data: data)
        parser.shouldProcessNamespaces = true
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse(), delegate.valid,
              delegate.values["Name"] == bucket, delegate.values["Prefix"] == prefix,
              delegate.values["MaxKeys"] == "1",
              ["true", "false"].contains(delegate.values["IsTruncated"] ?? ""),
              delegate.contentsCount <= 1 else { return false }
        // KeyCount is returned by R2/AWS V2, but tolerate compatible providers that omit it.
        if let count = delegate.values["KeyCount"], count != String(delegate.contentsCount) { return false }
        return true
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        if elements.isEmpty {
            if elementName != "ListBucketResult"
                || !(namespaceURI == nil || namespaceURI == "" || namespaceURI == "http://s3.amazonaws.com/doc/2006-03-01/") {
                valid = false
            }
        } else if elements.count == 1 {
            if Self.fields.contains(elementName) {
                if values[elementName] != nil { valid = false }
                values[elementName] = ""
            } else if elementName == "Contents" {
                contentsCount += 1
            }
        } else if elements.count == 2, Self.fields.contains(elements[1]) {
            valid = false
        }
        elements.append(elementName)
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if elements.count == 2, Self.fields.contains(elements[1]) {
            values[elements[1], default: ""] += string
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if !elements.isEmpty { elements.removeLast() }
    }
}

/// Parse only complete, bounded S3 Error documents. Never expose Message / Resource / request URLs.
private final class S3ErrorDocument: NSObject, XMLParserDelegate {
    private var elements = [String]()
    private var code = ""
    private var codeCount = 0
    private var valid = true

    static func code(in data: Data) -> String? {
        guard !data.isEmpty, data.count <= RemoteObjectLimits.errorBody else { return nil }
        // No DTDs/entities, including internally declared expansion payloads. Also reject UTF-16/32
        // here; normal S3 error XML is UTF-8, and unsupported encodings must fail closed.
        guard let text = String(data: data, encoding: .utf8), !text.contains("\0"),
              !text.contains("<!DOCTYPE"), !text.contains("<!ENTITY") else { return nil }
        let delegate = S3ErrorDocument()
        let parser = XMLParser(data: data)
        parser.shouldProcessNamespaces = true
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse(), delegate.valid, delegate.codeCount == 1 else { return nil }
        return delegate.code.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        if elements.isEmpty && elementName != "Error" { valid = false }
        if elements == ["Error"], elementName == "Code" { codeCount += 1 }
        if elements == ["Error", "Code"] { valid = false }
        elements.append(elementName)
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if elements == ["Error", "Code"] { code += string }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if !elements.isEmpty { elements.removeLast() }
    }
}

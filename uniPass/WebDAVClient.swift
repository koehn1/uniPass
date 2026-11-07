import Foundation
import Security

struct WebDAVConfiguration: Codable, Equatable {
    var serverURL: String = ""
    var username: String = ""
    var password: String = ""
    var allowInsecureHTTP: Bool = false
}

struct WebDAVDownload {
    let data: Data
    let etag: String?
}

enum WebDAVError: LocalizedError {
    case invalidURL
    case insecureHTTP
    case invalidCredentials
    case unsafeRedirect
    case authenticationFailed
    case accessDenied
    case notFound
    case conflict
    case preconditionFailed
    case missingETag
    case invalidETag
    case conflictingConditions
    case payloadTooLarge
    case invalidResponse
    case httpStatus(Int)
    case timedOut
    case networkFailure

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "The WebDAV URL is invalid. Enter the complete URL of an existing directory without credentials, query parameters, or fragments."
        case .insecureHTTP:
            return "Only HTTPS is allowed by default. Explicitly enable insecure HTTP only when necessary; HTTP transmits credentials and data in plaintext."
        case .invalidCredentials:
            return "A WebDAV username cannot contain a colon, and usernames and passwords cannot contain control characters."
        case .unsafeRedirect:
            return "The remote redirect was rejected. S3 does not allow redirects; WebDAV allows only same-origin redirects that preserve the request method."
        case .authenticationFailed:
            return "Remote authentication failed. Check the synchronization credentials."
        case .accessDenied:
            return "The remote server denied access. Check permissions."
        case .notFound:
            return "The remote directory, bucket, or resource does not exist. The app does not create directories or buckets automatically."
        case .conflict:
            return "The remote server returned a conflict (409). Check the remote configuration and download the data again."
        case .preconditionFailed:
            return "Remote data changed or the file already exists (412). Download it again and resolve the conflict instead of overwriting it."
        case .missingETag:
            return "The remote ETag is missing, so a safe update is impossible. Download the file first to obtain an ETag; if the server does not provide a strong ETag, safe replacement is unavailable."
        case .invalidETag:
            return "The server did not provide a strong ETag for safe updates, so replacement was refused."
        case .conflictingConditions:
            return "An existing file's ETag cannot be specified while creating a file."
        case .payloadTooLarge:
            return "The remote file or upload exceeds the size limit (50 MB for the vault and 32 MiB per attachment, excluding encryption overhead)."
        case .invalidResponse:
            return "The remote server returned an unrecognized response."
        case .httpStatus(let status):
            return "The remote request failed (HTTP \(status))."
        case .timedOut:
            return "The remote request timed out. Check the network and try again."
        case .networkFailure:
            return "The remote server could not be reached. Check the network, server URL, and HTTPS certificate."
        }
    }
}

protocol WebDAVServing {
    func testConnection() async throws
    func download() async throws -> WebDAVDownload?
    func upload(_ data: Data, expectedETag: String?, createOnly: Bool) async throws -> String?
    func downloadAttachment(id: UUID) async throws -> WebDAVDownload?
    func uploadAttachment(_ data: Data, id: UUID) async throws -> String?
}

extension WebDAVServing {
    func downloadAttachment(id: UUID) async throws -> WebDAVDownload? { throw WebDAVError.invalidResponse }
    func uploadAttachment(_ data: Data, id: UUID) async throws -> String? { throw WebDAVError.invalidResponse }
}

enum RemoteObjectLimits {
    static let vault = 50_000_000
    static let attachment = 32 * 1024 * 1024 + 28
    static let errorBody = 64 * 1024
}

actor WebDAVClient: WebDAVServing {
    // Decimal MB; the delegate enforces the same limit even without Content-Length.
    private static let maximumBytes = RemoteObjectLimits.vault
    private let directoryURL: URL
    private let vaultURL: URL
    private let authorization: String
    private let sessionConfiguration: URLSessionConfiguration

    init(configuration: WebDAVConfiguration,
         sessionConfiguration: URLSessionConfiguration = .ephemeral) throws {
        let address = configuration.serverURL
        guard address == address.trimmingCharacters(in: .whitespacesAndNewlines),
              var components = URLComponents(string: address),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.port.map({ (1...65535).contains($0) }) ?? true else {
            throw WebDAVError.invalidURL
        }
        // Foundation can silently discard overflowing ports; validate the original authority too.
        guard let authorityStart = address.range(of: "://")?.upperBound else { throw WebDAVError.invalidURL }
        let authority = address[authorityStart...].prefix { $0 != "/" && $0 != "?" && $0 != "#" }
        if let colon = authority.lastIndex(of: ":"), !authority[colon...].contains("]") {
            let rawPort = authority[authority.index(after: colon)...]
            guard !rawPort.isEmpty, rawPort.utf8.allSatisfy({ (48...57).contains($0) }),
                  let port = Int(rawPort), (1...65535).contains(port) else { throw WebDAVError.invalidURL }
        }
        guard scheme != "http" || configuration.allowInsecureHTTP else {
            throw WebDAVError.insecureHTTP
        }
        let credentials = configuration.username + configuration.password
        guard !configuration.username.contains(":"),
              !credentials.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw WebDAVError.invalidCredentials
        }
        components.scheme = scheme
        if !components.percentEncodedPath.hasSuffix("/") {
            components.percentEncodedPath += "/"
        }
        guard let directory = components.url else { throw WebDAVError.invalidURL }
        directoryURL = directory
        vaultURL = directory.appendingPathComponent("vault.enc", isDirectory: false)
        authorization = "Basic " + Data("\(configuration.username):\(configuration.password)".utf8).base64EncodedString()
        self.sessionConfiguration = sessionConfiguration.copy() as! URLSessionConfiguration
    }

    /// Tests the existing directory without creating or changing any remote data.
    func testConnection() async throws {
        let head = try await perform(method: "HEAD", url: directoryURL)
        if head.response.statusCode == 405 || head.response.statusCode == 501 {
            let body = Data("<?xml version=\"1.0\" encoding=\"utf-8\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/></d:prop></d:propfind>".utf8)
            let result = try await perform(method: "PROPFIND", url: directoryURL, body: body,
                                           headers: ["Depth": "0", "Content-Type": "application/xml; charset=utf-8"])
            try checkStatus(result.response.statusCode)
        } else {
            try checkStatus(head.response.statusCode)
        }
    }

    func download() async throws -> WebDAVDownload? {
        let result = try await perform(method: "GET", url: vaultURL)
        if result.response.statusCode == 404 { return nil }
        try checkStatus(result.response.statusCode)
        // Partial responses must never be treated as a complete encrypted vault.
        guard result.response.statusCode == 200 else { throw WebDAVError.invalidResponse }
        return WebDAVDownload(data: result.data, etag: result.response.value(forHTTPHeaderField: "ETag"))
    }

    /// Updates require a strong ETag from a previous download. There is no unconditional PUT.
    /// A successful PUT may return nil; fetch again before the next update in that case.
    func upload(_ data: Data, expectedETag: String?, createOnly: Bool) async throws -> String? {
        guard data.count <= Self.maximumBytes else { throw WebDAVError.payloadTooLarge }
        var headers = ["Content-Type": "application/octet-stream"]
        if createOnly {
            guard expectedETag == nil else { throw WebDAVError.conflictingConditions }
            headers["If-None-Match"] = "*"
        } else {
            guard let etag = expectedETag, !etag.isEmpty else { throw WebDAVError.missingETag }
            guard Self.isStrongETag(etag) else { throw WebDAVError.invalidETag }
            headers["If-Match"] = etag
        }
        let result = try await perform(method: "PUT", url: vaultURL, body: data, headers: headers)
        try checkStatus(result.response.statusCode)
        guard [200, 201, 204].contains(result.response.statusCode) else { throw WebDAVError.invalidResponse }
        return result.response.value(forHTTPHeaderField: "ETag")
    }

    func downloadAttachment(id: UUID) async throws -> WebDAVDownload? {
        let url = directoryURL.appendingPathComponent("attachment-\(id.uuidString).enc", isDirectory: false)
        let result = try await perform(method: "GET", url: url, maximumBytes: RemoteObjectLimits.attachment)
        if result.response.statusCode == 404 { return nil }
        try checkStatus(result.response.statusCode)
        guard result.response.statusCode == 200 else { throw WebDAVError.invalidResponse }
        return WebDAVDownload(data: result.data, etag: result.response.value(forHTTPHeaderField: "ETag"))
    }

    /// Immutable object: even a retry must not overwrite an existing attachment.
    func uploadAttachment(_ data: Data, id: UUID) async throws -> String? {
        guard data.count <= RemoteObjectLimits.attachment else { throw WebDAVError.payloadTooLarge }
        let url = directoryURL.appendingPathComponent("attachment-\(id.uuidString).enc", isDirectory: false)
        let result = try await perform(method: "PUT", url: url, body: data,
                                       headers: ["Content-Type": "application/octet-stream", "If-None-Match": "*"],
                                       maximumBytes: RemoteObjectLimits.attachment)
        try checkStatus(result.response.statusCode)
        guard [200, 201, 204].contains(result.response.statusCode) else { throw WebDAVError.invalidResponse }
        return result.response.value(forHTTPHeaderField: "ETag")
    }

    static func isStrongETag(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count >= 2, bytes.first == 0x22, bytes.last == 0x22 else { return false }
        // RFC 9110 entity-tag: one quoted opaque value, not W/…, *, or an ETag list.
        return bytes.dropFirst().dropLast().allSatisfy { $0 == 0x21 || (0x23...0x7E).contains($0) || $0 >= 0x80 }
    }

    private func checkStatus(_ status: Int) throws {
        switch status {
        case 200...299: return
        case 401: throw WebDAVError.authenticationFailed
        case 403: throw WebDAVError.accessDenied
        case 404: throw WebDAVError.notFound
        case 409: throw WebDAVError.conflict
        case 412: throw WebDAVError.preconditionFailed
        default: throw WebDAVError.httpStatus(status)
        }
    }

    private func perform(method: String, url: URL, body: Data? = nil,
                         headers: [String: String] = [:],
                         maximumBytes: Int = RemoteObjectLimits.vault) async throws -> RemoteResponse {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = method
        request.httpBody = body
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        return try await RemoteRequest(maximumBytes: maximumBytes, redirectPolicy: .sameOrigin,
                                       configuration: sessionConfiguration).run(request)
    }
}

struct RemoteResponse {
    let response: HTTPURLResponse
    let data: Data
    let errorBodyTruncated: Bool
}

/// One delegate/session per request avoids shared mutable response state across actor reentrancy.
/// State is locked because cancellation and URLSession delegate callbacks use different executors.
final class RemoteRequest: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    enum RedirectPolicy { case sameOrigin, rejectAll }

    private let redirectPolicy: RedirectPolicy
    private let configuration: URLSessionConfiguration
    private let lock = NSLock()
    private let maximumBytes: Int
    private var continuation: CheckedContinuation<RemoteResponse, Error>?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var originalRequest: URLRequest?
    private var response: HTTPURLResponse?
    private var buffer = Data()
    private var failure: Error?
    private var cancelled = false
    private var stoppedAfterHeaders = false
    private var errorBodyTruncated = false

    init(maximumBytes: Int, redirectPolicy: RedirectPolicy,
         configuration: URLSessionConfiguration = .ephemeral) {
        self.maximumBytes = maximumBytes
        self.redirectPolicy = redirectPolicy
        self.configuration = configuration.copy() as! URLSessionConfiguration
    }

    func run(_ request: URLRequest) async throws -> RemoteResponse {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                self.start(request, continuation: continuation)
            }
        }, onCancel: {
            self.cancel()
        })
    }

    private func start(_ request: URLRequest, continuation: CheckedContinuation<RemoteResponse, Error>) {
        lock.lock()
        if cancelled {
            lock.unlock()
            continuation.resume(throwing: CancellationError())
            return
        }
        let configuration = self.configuration.copy() as! URLSessionConfiguration
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCredentialStorage = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: request)
        self.continuation = continuation
        self.originalRequest = request
        self.session = session
        self.task = task
        lock.unlock()
        task.resume()
    }

    private func cancel() {
        lock.lock()
        cancelled = true
        let task = self.task
        lock.unlock()
        task?.cancel()
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        let disposition: URLSession.ResponseDisposition
        if let http = response as? HTTPURLResponse {
            self.response = http
            if failure != nil {
                disposition = .cancel
            } else if redirectPolicy == .rejectAll, (300...399).contains(http.statusCode) {
                failure = WebDAVError.unsafeRedirect
                disposition = .cancel
            } else if originalRequest?.httpMethod == "HEAD" {
                // A HEAD Content-Length describes the resource, not a response body.
                stoppedAfterHeaders = true
                disposition = .cancel
            } else if !(200...299).contains(http.statusCode) {
                // Read only a bounded prefix, preserving the HTTP status even for huge errors.
                disposition = .allow
            } else if response.expectedContentLength > Int64(maximumBytes) {
                failure = WebDAVError.payloadTooLarge
                disposition = .cancel
            } else {
                disposition = .allow
            }
        } else {
            failure = WebDAVError.invalidResponse
            disposition = .cancel
        }
        lock.unlock()
        completionHandler(disposition)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        let isError = response.map { !(200...299).contains($0.statusCode) } ?? false
        let limit = isError ? RemoteObjectLimits.errorBody : maximumBytes
        let tooLarge = data.count > limit - buffer.count
        if failure == nil && !stoppedAfterHeaders {
            if tooLarge && isError {
                buffer.append(data.prefix(limit - buffer.count))
                errorBodyTruncated = true
                stoppedAfterHeaders = true
            } else if tooLarge {
                failure = WebDAVError.payloadTooLarge
            } else {
                buffer.append(data)
            }
        }
        lock.unlock()
        if tooLarge { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        lock.lock()
        let original = originalRequest
        let safe = redirectPolicy == .sameOrigin && (original?.url.flatMap { origin in
            request.url.map { Self.sameOrigin(origin, $0) }
        } ?? false)
        let sameMethod = request.httpMethod == original?.httpMethod
        var redirect = request
        if safe && sameMethod {
            // Keep the upload body and preconditions intact if URLSession rebuilt the request.
            redirect.httpBody = original?.httpBody
            for (name, value) in original?.allHTTPHeaderFields ?? [:] {
                redirect.setValue(value, forHTTPHeaderField: name)
            }
        } else {
            failure = WebDAVError.unsafeRedirect
        }
        lock.unlock()
        completionHandler(safe && sameMethod ? redirect : nil)
    }

    private static func sameOrigin(_ first: URL, _ second: URL) -> Bool {
        guard let a = URLComponents(url: first, resolvingAgainstBaseURL: false),
              let b = URLComponents(url: second, resolvingAgainstBaseURL: false),
              b.user == nil, b.password == nil, b.query == nil, b.fragment == nil else { return false }
        func port(_ url: URLComponents) -> Int { url.port ?? (url.scheme?.lowercased() == "https" ? 443 : 80) }
        return a.scheme?.lowercased() == b.scheme?.lowercased()
            && a.host?.lowercased() == b.host?.lowercased() && port(a) == port(b)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil

        let result: Result<RemoteResponse, Error>
        if cancelled {
            result = .failure(CancellationError())
        } else if let failure = failure {
            result = .failure(failure)
        } else if stoppedAfterHeaders, let response = response {
            result = .success(RemoteResponse(response: response, data: buffer, errorBodyTruncated: errorBodyTruncated))
        } else if let response = response, !(200...299).contains(response.statusCode) {
            // Keep conditional failures even if the error body transfer fails. Incomplete XML
            // must never let S3 interpret a failed transfer as a missing object.
            result = .success(RemoteResponse(response: response, data: buffer,
                                             errorBodyTruncated: errorBodyTruncated || error != nil))
        } else if let error = error {
            // Do not expose NSError descriptions: they can contain server URLs and other secrets.
            let isTimeout = (error as? URLError)?.code == .timedOut
            result = .failure(isTimeout ? WebDAVError.timedOut : WebDAVError.networkFailure)
        } else if let response = response {
            result = .success(RemoteResponse(response: response, data: buffer, errorBodyTruncated: errorBodyTruncated))
        } else {
            result = .failure(WebDAVError.invalidResponse)
        }
        buffer = Data()
        self.task = nil
        self.session = nil
        originalRequest = nil
        lock.unlock()
        session.finishTasksAndInvalidate()
        continuation?.resume(with: result)
    }
}

enum KeychainCredentialError: LocalizedError {
    case emptyAccount
    case operationFailed(OSStatus)
    case invalidData

    var errorDescription: String? {
        switch self {
        case .emptyAccount: return "The Keychain account identifier cannot be empty."
        case .operationFailed(let status): return "The synchronization credential Keychain operation failed (status \(status))."
        case .invalidData: return "The synchronization credential data in Keychain is invalid."
        }
    }
}

/// Store encoded sync credentials here, never in UserDefaults. No biometric ACL is used.
/// Keep the existing service and caller-supplied accounts for migration compatibility.
enum KeychainCredentialStore {
    private static let service = (Bundle.main.bundleIdentifier ?? "com.unipass.unipass") + ".webdav.credentials.v1"

    private static func query(account: String) throws -> [String: Any] {
        guard !account.isEmpty else { throw KeychainCredentialError.emptyAccount }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: false]
    }

    static func save(_ data: Data, account: String) throws {
        let query = try query(account: account)
        let attributes: [String: Any] = [kSecValueData as String: data,
                                       kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            attributes.forEach { item[$0.key] = $0.value }
            status = SecItemAdd(item as CFDictionary, nil)
            if status == errSecDuplicateItem {
                status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            }
        }
        guard status == errSecSuccess else { throw KeychainCredentialError.operationFailed(status) }
    }

    static func load(account: String) throws -> Data? {
        var query = try query(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainCredentialError.operationFailed(status) }
        guard let data = result as? Data else { throw KeychainCredentialError.invalidData }
        return data
    }

    static func delete(account: String) throws {
        let status = SecItemDelete(try query(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainCredentialError.operationFailed(status)
        }
    }
}

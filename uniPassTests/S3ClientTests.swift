import Foundation
import XCTest
@testable import uniPass

final class S3ClientTests: XCTestCase {
    private let date = ISO8601DateFormatter().date(from: "2013-05-24T00:00:00Z")!
    private let accessKey = "AKIAIOSFODNN7EXAMPLE"
    private let secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    // Official AWS S3 single-chunk SigV4 examples (including their slash, not plus, secret):
    // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
    func testOfficialAWSGetObjectVector() {
        let hash = S3Signer.sha256(Data())
        XCTAssertEqual(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        let result = sign(method: "GET", uri: "/test.txt", headers: ["Range": "bytes=0-9"])
        XCTAssertEqual(result.canonicalHeaders, "host:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:\(hash)\nx-amz-date:20130524T000000Z\n")
        XCTAssertEqual(result.canonicalRequest, "GET\n/test.txt\n\n\(result.canonicalHeaders)\nhost;range;x-amz-content-sha256;x-amz-date\n\(hash)")
        XCTAssertEqual(S3Signer.sha256(Data(result.canonicalRequest.utf8)), "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972")
        XCTAssertEqual(result.signature, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
        XCTAssertEqual(result.authorization, "AWS4-HMAC-SHA256 Credential=\(accessKey)/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=\(result.signature)")
    }

    func testOfficialAWSPutObjectVector() {
        let payload = Data("Welcome to Amazon S3.".utf8)
        XCTAssertEqual(S3Signer.sha256(payload), "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")
        let result = sign(method: "PUT", uri: "/test%24file.text", headers: [
            "Date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY"
        ], payload: payload)
        XCTAssertEqual(S3Signer.sha256(Data(result.canonicalRequest.utf8)), "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d")
        XCTAssertEqual(result.signature, "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")
    }

    func testOfficialAWSListVector() {
        let result = sign(method: "GET", uri: "/", query: "max-keys=2&prefix=J")
        XCTAssertEqual(S3Signer.sha256(Data(result.canonicalRequest.utf8)), "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7")
        XCTAssertEqual(result.signature, "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
    }

    func testEncodingPreservesRawUTF8AndNeverNormalizes() {
        XCTAssertEqual(S3Signer.uriEncode("AZaz09-._~ /+%?#"), "AZaz09-._~%20%2F%2B%25%3F%23")
        XCTAssertEqual(S3Signer.uriEncode("/café/100%/a+b", encodeSlash: false), "/caf%C3%A9/100%25/a%2Bb")
        XCTAssertEqual(S3Signer.uriEncode("%2F"), "%252F")
        XCTAssertEqual(S3Signer.uriEncode("e\u{301}"), "e%CC%81")
        XCTAssertEqual(S3Signer.uriEncode("é"), "%C3%A9")
        XCTAssertEqual(S3Signer.uriEncode("/a//./../b", encodeSlash: false), "/a//./../b")
        let result = sign(method: "GET", uri: "/", headers: ["Range": " \tbytes=0-9\t "])
        XCTAssertTrue(result.canonicalHeaders.contains("range:bytes=0-9\n"))
    }

    func testConfigurationDefaultsAndCodable() throws {
        XCTAssertEqual(S3Configuration(), S3Configuration(endpoint: "", bucket: "", region: "auto", accessKeyID: "", secretAccessKey: "", prefix: ""))
        let config = configuration()
        XCTAssertEqual(try JSONDecoder().decode(S3Configuration.self, from: JSONEncoder().encode(config)), config)
        XCTAssertNoThrow(try S3Client(configuration: config))
        var r2 = config
        r2.endpoint = "https://account.r2.cloudflarestorage.com"
        XCTAssertNoThrow(try S3Client(configuration: r2))
    }

    func testRejectsUnsafeConfigurationBeforeNetworking() {
        for endpoint in ["", "http://s3.invalid", "https://u:p@s3.invalid", "https://s3.invalid/path",
                         "https://s3.invalid?", "https://s3.invalid#", " https://s3.invalid", "https://s3.invalid:0",
                         "https://s3.invalid:65536", "https://s3.invalid:999999999999999999999", "https://s3.invalid:",
                         "https://s3.invalid\\evil", "https://r2.dev", "https://public.r2.dev"] {
            var config = configuration(); config.endpoint = endpoint
            XCTAssertThrowsError(try S3Client(configuration: config), endpoint)
        }
        for bucket in ["", "ab", "Uppercase", "a/b", "a..b", "a.-b", "-bucket", "bucket-", "127.0.0.1",
                       "a%2Fb", "a_b", "a\\b", "a\nb", "a?b", "a#b", String(repeating: "a", count: 64)] {
            var config = configuration(); config.bucket = bucket
            XCTAssertThrowsError(try S3Client(configuration: config), bucket)
        }
        for prefix in ["/", "/start", "end/", "a//b", ".", "..", "a/./b", "a/../b", String(repeating: "a", count: 1100)] {
            var config = configuration(); config.prefix = prefix
            XCTAssertThrowsError(try S3Client(configuration: config), prefix)
        }
        for prefix in ["", "café/e\u{301}/%2F +?#", "a/.../b"] {
            var config = configuration(); config.prefix = prefix
            XCTAssertNoThrow(try S3Client(configuration: config))
        }
        var config = configuration(); config.region = "auto\n"
        XCTAssertThrowsError(try S3Client(configuration: config))
        config = configuration(); config.accessKeyID = "key/id"
        XCTAssertThrowsError(try S3Client(configuration: config))
        config = configuration(); config.accessKeyID = "ASIATEMPORARY"
        XCTAssertThrowsError(try S3Client(configuration: config))
        config = configuration(); config.secretAccessKey = "secret\r\n"
        XCTAssertThrowsError(try S3Client(configuration: config))
    }

    func testBucketValidationAllowsProviderSpecificNamesAndDottedS3Buckets() throws {
        for bucket in ["xn--bucket", "sthree-backup", "amzn-s3-demo-backup", "backup-s3alias",
                       "backup--ol-s3", "backup.mrap", "backup--x-s3", "backup--table-s3", "my.s3.bucket"] {
            var config = configuration(); config.bucket = bucket
            XCTAssertNoThrow(try S3Client(configuration: config), bucket)
        }
    }

    func testCanonicalQueryEncodesBeforeSortingAndPreservesDuplicateNames() {
        XCTAssertEqual(S3Signer.canonicalQuery([]), "")
        XCTAssertEqual(S3Signer.canonicalQuery([("prefix", "a/b +%2F?&=café"), ("max-keys", "1"), ("list-type", "2")]),
                       "list-type=2&max-keys=1&prefix=a%2Fb%20%2B%252F%3F%26%3Dcaf%C3%A9")
        // Encoded non-ASCII sorts before ASCII; sort duplicate names by their encoded values.
        XCTAssertEqual(S3Signer.canonicalQuery([("z", ""), ("é", "e\u{301}"), ("a", "z"), ("a", "/"), ("a", " ")]),
                       "%C3%A9=e%CC%81&a=%20&a=%2F&a=z&z=")
    }

    func testEncodedPathMatchesSignatureWithoutDoubleEncoding() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        var config = configuration(endpoint: stub.endpoint + ":9443")
        config.prefix = "café/e\u{301}/%2F +?#"
        let fixedDate = date
        stub.handle { request, protocolInstance in
            let uri = "/test-bucket/caf%C3%A9/e%CC%81/%252F%20%2B%3F%23/vault.enc"
            XCTAssertEqual(URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.percentEncodedPath, uri)
            XCTAssertEqual(request.value(forHTTPHeaderField: "Host"), stub.host + ":9443")
            XCTAssertEqual(request.value(forHTTPHeaderField: "x-amz-date"), "20130524T000000Z")
            XCTAssertNil(request.value(forHTTPHeaderField: "x-amz-security-token"))
            let signature = S3Signer.sign(method: "GET", canonicalURI: uri, headers: [
                "host": stub.host + ":9443", "x-amz-date": "20130524T000000Z",
                "x-amz-content-sha256": S3Signer.sha256(Data())
            ], payloadHash: S3Signer.sha256(Data()), accessKeyID: "testkey", secretAccessKey: "testsecret", region: "auto", date: fixedDate)
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), signature.authorization)
            protocolInstance.respond(status: 200, headers: ["ETag": "\"remote\""], chunks: [Data([1, 2, 3])])
        }
        let client = try S3Client(configuration: config, sessionConfiguration: stub.sessionConfiguration, now: { fixedDate })
        let downloaded = try await client.download()
        XCTAssertEqual(downloaded?.data, Data([1, 2, 3]))
        XCTAssertEqual(downloaded?.etag, "\"remote\"")
    }

    func testConditionalVaultAndAttachmentPutsAreSigned() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let fixedDate = date
        let payload = Data("encrypted".utf8)
        let id = UUID()
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint),
                                  sessionConfiguration: stub.sessionConfiguration, now: { fixedDate })
        for (etag, createOnly, attachment) in [(nil, true, false), (Optional("\"old\""), false, false), (nil, true, true)] {
            stub.handle { request, protocolInstance in
                XCTAssertEqual(request.httpMethod, "PUT")
                let condition = createOnly ? "if-none-match" : "if-match"
                let value = createOnly ? "*" : etag!
                XCTAssertEqual(request.value(forHTTPHeaderField: condition), value)
                XCTAssertNil(request.value(forHTTPHeaderField: createOnly ? "if-match" : "if-none-match"))
                let uri = "/test-bucket/" + (attachment ? "attachment-\(id.uuidString).enc" : "vault.enc")
                XCTAssertEqual(request.url?.path, uri)
                let hash = S3Signer.sha256(payload)
                XCTAssertEqual(request.value(forHTTPHeaderField: "x-amz-content-sha256"), hash)
                let signed = S3Signer.sign(method: "PUT", canonicalURI: uri, headers: [
                    "host": stub.host, "content-type": "application/octet-stream", condition: value,
                    "x-amz-date": "20130524T000000Z", "x-amz-content-sha256": hash
                ], payloadHash: hash, accessKeyID: "testkey", secretAccessKey: "testsecret", region: "auto", date: fixedDate)
                XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), signed.authorization)
                XCTAssertTrue(signed.signedHeaders.contains(condition))
                protocolInstance.respond(status: 200, headers: ["ETag": "\"new\""])
            }
            let result: String?
            if attachment { result = try await client.uploadAttachment(payload, id: id) }
            else { result = try await client.upload(payload, expectedETag: etag, createOnly: createOnly) }
            XCTAssertEqual(result, "\"new\"")
        }
    }

    func testUnsafeConditionsAndOversizedUploadsNeverReachNetwork() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        stub.handle { _, protocolInstance in
            XCTFail("Invalid upload contacted network")
            protocolInstance.respond(status: 500)
        }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        for (etag, createOnly) in [(nil, false), (Optional(""), false), (Optional("W/\"weak\""), false),
                                   (Optional("*"), false), (Optional("\"a\", \"b\""), false),
                                   (Optional("\"line\r\n\""), false), (Optional("\"old\""), true)] {
            do {
                _ = try await client.upload(Data(), expectedETag: etag, createOnly: createOnly)
                XCTFail("Expected condition rejection")
            } catch {
                guard let error = error as? WebDAVError else { return XCTFail("Unexpected error type") }
                switch error {
                case .missingETag, .invalidETag, .conflictingConditions: break
                default: XCTFail("Unexpected error: \(error)")
                }
            }
        }
        do {
            _ = try await client.uploadAttachment(Data(count: RemoteObjectLimits.attachment + 1), id: UUID())
            XCTFail("Expected size rejection")
        } catch { assertError(error, status: 413) }
        do {
            _ = try await client.upload(Data(count: RemoteObjectLimits.vault + 1), expectedETag: nil, createOnly: true)
            XCTFail("Expected size rejection")
        } catch { assertError(error, status: 413) }
        for value in ["\"\"", "\"multi-part-2\"", "\"abc\""] { XCTAssertTrue(WebDAVClient.isStrongETag(value)) }
        for value in ["*", "W/\"weak\"", "\"a\",\"b\"", "\"a\n\"", "unquoted"] { XCTAssertFalse(WebDAVClient.isStrongETag(value)) }
    }

    func testOnlyCompleteNoSuchKey404MeansMissingForVaultAndAttachments() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        for attachment in [false, true] {
            stub.handle { _, protocolInstance in
                protocolInstance.respond(status: 404, chunks: [Data("<?xml version=\"1.0\"?><Error xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Code>NoSuchKey</Code></Error>".utf8)])
            }
            let result = try await (attachment ? client.downloadAttachment(id: UUID()) : client.download())
            XCTAssertNil(result)
            for body in ["", "<Error><Code>NoSuchBucket</Code></Error>", "<Error><Code>AccessDenied</Code></Error>",
                         "<Error><Code>NoSuchKey</Code>", "<Other><Code>NoSuchKey</Code></Other>",
                         "<Error><Code>NoSuchKey</Code><Code>NoSuchBucket</Code></Error>",
                         "<!DOCTYPE Error [<!ENTITY key 'NoSuchKey'>]><Error><Code>&key;</Code></Error>",
                         "<Error><Code><Nested/>NoSuchKey</Code></Error>"] {
                stub.handle { _, protocolInstance in protocolInstance.respond(status: 404, chunks: [Data(body.utf8)]) }
                do {
                    _ = try await (attachment ? client.downloadAttachment(id: UUID()) : client.download())
                    XCTFail("Non-NoSuchKey error treated as success")
                } catch { assertError(error, status: 404) }
            }
        }
    }

    func testHTTP403409412AndPartialResponses() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        for status in [403, 409, 412] {
            for attachment in [false, true] {
                stub.handle { _, protocolInstance in
                    protocolInstance.respond(status: status, chunks: [Data(repeating: 120, count: RemoteObjectLimits.errorBody + 1)])
                }
                do {
                    if attachment { _ = try await client.uploadAttachment(Data(), id: UUID()) }
                    else { _ = try await client.upload(Data(), expectedETag: "\"old\"", createOnly: false) }
                    XCTFail("Expected HTTP failure")
                } catch { assertError(error, status: status) }
            }
        }
        stub.handle { _, protocolInstance in protocolInstance.respond(status: 206, chunks: [Data([1])]) }
        do { _ = try await client.download(); XCTFail("Partial data accepted") }
        catch { guard case WebDAVError.invalidResponse = error else { return XCTFail("Unexpected error") } }
    }

    func testInterruptedErrorBodiesPreserveObservedStatus() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        for status in [404, 409, 412] {
            let transport = RemoteRequest(maximumBytes: 100, redirectPolicy: .rejectAll, configuration: stub.sessionConfiguration)
            let xml = Data("<Error><Code>NoSuchKey</Code></Error>".utf8)
            stub.handle { request, protocolInstance in
                // URLProtocol may discard its queued response/data callbacks when immediately
                // failed. Drive the delegate directly to guarantee the headers were observed,
                // then let the real session deliver the transport failure and completion.
                let session = URLSession(configuration: .ephemeral)
                defer { session.invalidateAndCancel() }
                let task = session.dataTask(with: request)
                let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
                transport.urlSession(session, dataTask: task, didReceive: response) { disposition in
                    XCTAssertEqual(disposition, .allow)
                }
                transport.urlSession(session, dataTask: task, didReceive: xml)
                protocolInstance.client?.urlProtocol(protocolInstance, didFailWithError: URLError(.networkConnectionLost))
            }
            let result = try await transport.run(URLRequest(url: URL(string: stub.endpoint + "/object")!))
            XCTAssertEqual(result.response.statusCode, status)
            XCTAssertEqual(result.data, xml)
            // Even syntactically complete XML cannot mean NoSuchKey after a failed transfer.
            XCTAssertTrue(result.errorBodyTruncated)
        }
    }

    func testImmediateURLProtocolFailureNeverMeansMissingOrSuccessfulUpload() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        for status in [404, 409, 412] {
            stub.handle { request, protocolInstance in
                let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
                protocolInstance.client?.urlProtocol(protocolInstance, didReceive: response, cacheStoragePolicy: .notAllowed)
                protocolInstance.client?.urlProtocol(protocolInstance, didLoad: Data("<Error><Code>NoSuchKey</Code></Error>".utf8))
                protocolInstance.client?.urlProtocol(protocolInstance, didFailWithError: URLError(.networkConnectionLost))
            }
            do {
                if status == 404 { _ = try await client.download() }
                else { _ = try await client.uploadAttachment(Data(), id: UUID()) }
                XCTFail("Interrupted error body treated as success")
            } catch {
                // Both schedules are valid: if Foundation withheld the headers, there is no
                // HTTP status to preserve. Never infer one from URLProtocol's sent callbacks.
                if case WebDAVError.networkFailure = error { continue }
                assertError(error, status: status)
            }
        }
    }

    func testOptionalETagsAndUnexpectedSuccessStatuses() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        stub.handle { _, protocolInstance in protocolInstance.respond(status: 201) }
        let etag = try await client.upload(Data(), expectedETag: nil, createOnly: true)
        XCTAssertNil(etag)
        stub.handle { _, protocolInstance in protocolInstance.respond(status: 200, chunks: [Data([42])]) }
        let object = try await client.downloadAttachment(id: UUID())
        XCTAssertEqual(object?.data, Data([42]))
        XCTAssertNil(object?.etag)
        stub.handle { _, protocolInstance in protocolInstance.respond(status: 202) }
        do { _ = try await client.uploadAttachment(Data(), id: UUID()); XCTFail("Unexpected 202 accepted") }
        catch { guard case WebDAVError.invalidResponse = error else { return XCTFail("Unexpected error") } }
        stub.handle { _, protocolInstance in protocolInstance.respond(status: 204) }
        do { _ = try await client.download(); XCTFail("Empty 204 accepted as complete vault") }
        catch { guard case WebDAVError.invalidResponse = error else { return XCTFail("Unexpected error") } }
    }

    func testConnectionListsOnlyConfiguredPrefixWithSignedEncodedQuery() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let fixedDate = date
        for (prefix, encodedPrefix) in [
            ("", ""), ("nested/folder", "nested%2Ffolder%2F"),
            ("café/e\u{301}/%2F +?#&=<", "caf%C3%A9%2Fe%CC%81%2F%252F%20%2B%3F%23%26%3D%3C%2F")
        ] {
            var config = configuration(endpoint: stub.endpoint + ":9443")
            config.bucket = "my.s3.bucket"
            config.prefix = prefix
            let requestedPrefix = prefix.isEmpty ? "" : prefix + "/"
            let query = "list-type=2&max-keys=1&prefix=" + encodedPrefix
            let called = expectation(description: "One read-only list request")
            called.assertForOverFulfill = true
            let xml = listResponse(bucket: config.bucket, prefix: requestedPrefix)
            stub.handle { request, protocolInstance in
                called.fulfill()
                XCTAssertEqual(request.httpMethod, "GET")
                XCTAssertNil(request.httpBody)
                let components = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)
                XCTAssertEqual(components?.percentEncodedPath, "/my.s3.bucket")
                XCTAssertEqual(components?.percentEncodedQuery, query)
                XCTAssertEqual(components?.queryItems?.first(where: { $0.name == "prefix" })?.value, requestedPrefix)
                let hash = S3Signer.sha256(Data())
                let signed = S3Signer.sign(method: "GET", canonicalURI: "/my.s3.bucket", canonicalQuery: query, headers: [
                    "host": stub.host + ":9443", "x-amz-date": "20130524T000000Z", "x-amz-content-sha256": hash
                ], payloadHash: hash, accessKeyID: "testkey", secretAccessKey: "testsecret", region: "auto", date: fixedDate)
                XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), signed.authorization)
                XCTAssertEqual(request.value(forHTTPHeaderField: "x-amz-content-sha256"), hash)
                protocolInstance.respond(status: 200, chunks: [xml])
            }
            let client = try S3Client(configuration: config, sessionConfiguration: stub.sessionConfiguration, now: { fixedDate })
            try await client.testConnection()
            await fulfillment(of: [called], timeout: 3)
        }
    }

    func testConnectionAcceptsValidEmptyAndNonemptyListXML() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        let empty = String(decoding: listResponse(), as: UTF8.self)
        for xml in [empty,
                    empty.replacingOccurrences(of: " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"", with: ""),
                    empty.replacingOccurrences(of: "<KeyCount>0</KeyCount>", with: ""),
                    empty.replacingOccurrences(of: "<KeyCount>0</KeyCount>", with: "<KeyCount>1</KeyCount><Contents><Key>vault.enc</Key><Size>42</Size></Contents>")
                        .replacingOccurrences(of: "<IsTruncated>false</IsTruncated>", with: "<IsTruncated>true</IsTruncated><NextContinuationToken>opaque</NextContinuationToken>")] {
            stub.handle { request, protocolInstance in
                XCTAssertEqual(request.httpMethod, "GET")
                XCTAssertNil(request.httpBody)
                protocolInstance.respond(status: 200, chunks: [Data(xml.utf8)])
            }
            try await client.testConnection()
        }
    }

    func testConnectionRejectsErrorsWithoutFallbackOrWrites() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        for status in [401, 403, 404, 409, 412, 500, 307] {
            let called = expectation(description: "HTTP \(status) must not trigger permission fallback")
            called.assertForOverFulfill = true
            stub.handle { request, protocolInstance in
                called.fulfill()
                XCTAssertEqual(request.httpMethod, "GET")
                XCTAssertNil(request.httpBody)
                XCTAssertEqual(URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.percentEncodedQuery,
                               "list-type=2&max-keys=1&prefix=")
                // Even NoSuchKey is an error for the list probe, never an empty-bucket success.
                protocolInstance.respond(status: status, headers: ["Location": stub.endpoint + "/other"],
                                         chunks: [Data("<Error><Code>NoSuchKey</Code></Error>".utf8)])
            }
            do { try await client.testConnection(); XCTFail("HTTP error accepted") }
            catch { assertError(error, status: status) }
            await fulfillment(of: [called], timeout: 3)
        }
    }

    func testConnectionRejectsInvalidOrOversizedListResponses() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        let valid = String(decoding: listResponse(), as: UTF8.self)
        for xml in ["", "<html><body>Sign in</body></html>", "<Error><Code>AccessDenied</Code></Error>",
                    "<ListBucketResult/>", "<Other>\(valid)</Other>", String(valid.dropLast()),
                    valid.replacingOccurrences(of: "test-bucket", with: "another-bucket"),
                    valid.replacingOccurrences(of: "<Prefix></Prefix>", with: "<Prefix>wrong/</Prefix>"),
                    valid.replacingOccurrences(of: "<MaxKeys>1</MaxKeys>", with: "<MaxKeys>1000</MaxKeys>"),
                    valid.replacingOccurrences(of: "<IsTruncated>false</IsTruncated>", with: "<IsTruncated>unknown</IsTruncated>"),
                    valid.replacingOccurrences(of: "<KeyCount>0</KeyCount>", with: "<KeyCount>1</KeyCount>"),
                    valid.replacingOccurrences(of: "<Name>test-bucket</Name>", with: "<Name>test-bucket</Name><Name>test-bucket</Name>"),
                    valid.replacingOccurrences(of: "<Name>test-bucket</Name>", with: "<Name><Nested/>test-bucket</Name>"),
                    valid.replacingOccurrences(of: "http://s3.amazonaws.com/doc/2006-03-01/", with: "https://example.invalid/html"),
                    "<!DOCTYPE ListBucketResult [<!ENTITY b 'test-bucket'>]>" + valid,
                    valid + "<html/>"] {
            stub.handle { request, protocolInstance in
                XCTAssertEqual(request.httpMethod, "GET")
                protocolInstance.respond(status: 200, chunks: [Data(xml.utf8)])
            }
            do { try await client.testConnection(); XCTFail("Invalid listing accepted") }
            catch { guard case WebDAVError.invalidResponse = error else { return XCTFail("Unexpected error") } }
        }
        for status in [201, 204, 206] {
            stub.handle { _, protocolInstance in protocolInstance.respond(status: status, chunks: [Data(valid.utf8)]) }
            do { try await client.testConnection(); XCTFail("Non-200 listing accepted") }
            catch { guard case WebDAVError.invalidResponse = error else { return XCTFail("Unexpected error") } }
        }
        for headers in [["Content-Length": String(RemoteObjectLimits.errorBody + 1)], [:]] {
            stub.handle { _, protocolInstance in
                protocolInstance.respond(status: 200, headers: headers, chunks: [Data(count: RemoteObjectLimits.errorBody + 1)])
            }
            do { try await client.testConnection(); XCTFail("Unbounded listing accepted") }
            catch { assertError(error, status: 413) }
        }
    }

    func testS3RejectsEveryRedirectStatusIncludingSameOrigin() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        for status in [301, 302, 303, 307, 308] {
            stub.handle { _, protocolInstance in
                protocolInstance.respond(status: status, headers: ["Location": stub.endpoint + "/elsewhere"])
            }
            do { _ = try await client.download(); XCTFail("Redirect accepted") }
            catch { guard case WebDAVError.unsafeRedirect = error else { return XCTFail("Unexpected redirect error") } }
        }
    }

    func testRedirectDelegatePreservesWebDAVButRefusesS3() async throws {
        // URLProtocol's wasRedirectedTo callback is unsupported by some Foundation versions.
        // Exercise the actual delegate decision directly while a stubbed request is active.
        for (policy, target, method, allowed) in [
            (RemoteRequest.RedirectPolicy.sameOrigin, "/moved", "PUT", true),
            (.sameOrigin, "https://other.invalid/moved", "PUT", false),
            (.sameOrigin, "/moved", "GET", false),
            (.rejectAll, "/moved", "PUT", false)
        ] {
            let stub = S3ProtocolFixture()
            defer { stub.remove() }
            let transport = RemoteRequest(maximumBytes: 100, redirectPolicy: policy, configuration: stub.sessionConfiguration)
            stub.handle { original, protocolInstance in
                let session = URLSession(configuration: .ephemeral)
                defer { session.invalidateAndCancel() }
                let task = session.dataTask(with: original)
                var redirect = URLRequest(url: URL(string: target.hasPrefix("https:") ? target : stub.endpoint + target)!)
                redirect.httpMethod = method
                let response = HTTPURLResponse(url: original.url!, statusCode: 307, httpVersion: "HTTP/1.1", headerFields: nil)!
                transport.urlSession(session, task: task, willPerformHTTPRedirection: response, newRequest: redirect) { forwarded in
                    XCTAssertEqual(forwarded != nil, allowed)
                    if allowed {
                        XCTAssertEqual(forwarded?.httpBody, Data([1, 2]))
                        XCTAssertEqual(forwarded?.value(forHTTPHeaderField: "If-None-Match"), "*")
                        XCTAssertEqual(forwarded?.value(forHTTPHeaderField: "Authorization"), "Basic test")
                    }
                }
                protocolInstance.respond(status: 200)
            }
            var request = URLRequest(url: URL(string: stub.endpoint + "/original")!)
            request.httpMethod = "PUT"; request.httpBody = Data([1, 2])
            request.setValue("*", forHTTPHeaderField: "If-None-Match")
            request.setValue("Basic test", forHTTPHeaderField: "Authorization")
            do {
                _ = try await transport.run(request)
                XCTAssertTrue(allowed)
            } catch {
                XCTAssertFalse(allowed)
                guard case WebDAVError.unsafeRedirect = error else { return XCTFail("Unexpected error") }
            }
        }
    }

    func testResponseLimitsWithAndWithoutContentLengthAndBoundedErrors() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let request = URLRequest(url: URL(string: stub.endpoint + "/object")!)
        XCTAssertEqual(RemoteObjectLimits.attachment, 33_554_460)
        XCTAssertEqual(RemoteObjectLimits.vault, 50_000_000)
        stub.handle { _, protocolInstance in protocolInstance.respond(status: 200, chunks: [Data(count: 8)]) }
        let atLimit = try await RemoteRequest(maximumBytes: 8, redirectPolicy: .rejectAll, configuration: stub.sessionConfiguration).run(request)
        XCTAssertEqual(atLimit.data.count, 8)
        for headers in [["Content-Length": "9"], [:]] {
            stub.handle { _, protocolInstance in protocolInstance.respond(status: 200, headers: headers, chunks: [Data(count: 4), Data(count: 5)]) }
            do {
                _ = try await RemoteRequest(maximumBytes: 8, redirectPolicy: .rejectAll, configuration: stub.sessionConfiguration).run(request)
                XCTFail("Oversized response accepted")
            } catch { assertError(error, status: 413) }
        }
        stub.handle { _, protocolInstance in
            protocolInstance.respond(status: 412, headers: ["Content-Length": "999999999"],
                                     chunks: [Data(repeating: 120, count: RemoteObjectLimits.errorBody + 1)])
        }
        let bounded = try await RemoteRequest(maximumBytes: 8, redirectPolicy: .rejectAll, configuration: stub.sessionConfiguration).run(request)
        XCTAssertEqual(bounded.response.statusCode, 412)
        XCTAssertEqual(bounded.data.count, RemoteObjectLimits.errorBody)
        XCTAssertTrue(bounded.errorBodyTruncated)

        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        for attachment in [false, true] {
            let maximum = attachment ? RemoteObjectLimits.attachment : RemoteObjectLimits.vault
            stub.handle { _, protocolInstance in protocolInstance.respond(status: 200, headers: ["Content-Length": String(maximum + 1)]) }
            do {
                _ = try await (attachment ? client.downloadAttachment(id: UUID()) : client.download())
                XCTFail("Declared oversized object accepted")
            } catch { assertError(error, status: 413) }
        }
        stub.handle { _, protocolInstance in
            let xml = "<Error><Code>NoSuchKey</Code></Error>" + String(repeating: " ", count: RemoteObjectLimits.errorBody)
            protocolInstance.respond(status: 404, chunks: [Data(xml.utf8)])
        }
        do { _ = try await client.download(); XCTFail("Truncated XML accepted as missing") }
        catch { assertError(error, status: 404) }
    }

    func testCancellationBeforeAndDuringRequest() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        let started = expectation(description: "URLProtocol started")
        let stopped = expectation(description: "URLProtocol stopped")
        stub.handle(onStop: { stopped.fulfill() }) { request, protocolInstance in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            protocolInstance.client?.urlProtocol(protocolInstance, didReceive: response, cacheStoragePolicy: .notAllowed)
            protocolInstance.client?.urlProtocol(protocolInstance, didLoad: Data([1]))
            started.fulfill()
            // Leave the streamed response open until the task is cancelled.
        }
        let task = Task { try await client.download() }
        await fulfillment(of: [started], timeout: 3)
        task.cancel()
        do { _ = try await task.value; XCTFail("Cancellation ignored") }
        catch { XCTAssertTrue(error is CancellationError) }
        await fulfillment(of: [stopped], timeout: 3)

        let neverStarted = expectation(description: "Cancelled task must not start network")
        neverStarted.isInverted = true
        stub.handle { _, protocolInstance in neverStarted.fulfill(); protocolInstance.respond(status: 200) }
        let cancelled = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await client.download()
        }
        do { _ = try await cancelled.value; XCTFail("Early cancellation ignored") }
        catch { XCTAssertTrue(error is CancellationError) }
        await fulfillment(of: [neverStarted], timeout: 0.05)
    }

    func testNetworkErrorsAreSanitized() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try S3Client(configuration: configuration(endpoint: stub.endpoint), sessionConfiguration: stub.sessionConfiguration)
        for code in [URLError.Code.timedOut, .cannotConnectToHost] {
            stub.handle { _, protocolInstance in
                protocolInstance.client?.urlProtocol(protocolInstance, didFailWithError: URLError(code, userInfo: [
                    NSURLErrorFailingURLStringErrorKey: "https://private.invalid/SECRET", NSLocalizedDescriptionKey: "SECRET"
                ]))
            }
            do { _ = try await client.download(); XCTFail("Expected network failure") }
            catch {
                XCTAssertFalse(error.localizedDescription.contains("SECRET"))
                XCTAssertFalse(error.localizedDescription.contains("private.invalid"))
                guard let remote = error as? WebDAVError else { return XCTFail("Raw error escaped") }
                switch (code, remote) {
                case (.timedOut, .timedOut), (.cannotConnectToHost, .networkFailure): break
                default: XCTFail("Wrong sanitized error")
                }
            }
        }
    }

    func testWebDAVAttachmentsStayFlatAndCreateOnly() async throws {
        let stub = S3ProtocolFixture()
        defer { stub.remove() }
        let client = try WebDAVClient(configuration: WebDAVConfiguration(serverURL: stub.endpoint + "/existing/"), sessionConfiguration: stub.sessionConfiguration)
        let id = UUID()
        stub.handle { request, protocolInstance in
            XCTAssertEqual(request.httpMethod, "PUT")
            XCTAssertEqual(request.url?.path, "/existing/attachment-\(id.uuidString).enc")
            XCTAssertEqual(request.value(forHTTPHeaderField: "If-None-Match"), "*")
            XCTAssertNil(request.value(forHTTPHeaderField: "If-Match"))
            protocolInstance.respond(status: 201, headers: ["ETag": "\"attachment\""])
        }
        let etag = try await client.uploadAttachment(Data([1]), id: id)
        XCTAssertEqual(etag, "\"attachment\"")
        stub.handle { request, protocolInstance in
            XCTAssertEqual(request.httpMethod, "GET")
            XCTAssertEqual(request.url?.path, "/existing/attachment-\(id.uuidString).enc")
            protocolInstance.respond(status: 200, chunks: [Data([1])])
        }
        let downloaded = try await client.downloadAttachment(id: id)
        XCTAssertEqual(downloaded?.data, Data([1]))
        stub.handle { _, protocolInstance in protocolInstance.respond(status: 404) }
        let missing = try await client.downloadAttachment(id: id)
        XCTAssertNil(missing)
        stub.handle { _, protocolInstance in protocolInstance.respond(status: 412) }
        do { _ = try await client.uploadAttachment(Data([1]), id: id); XCTFail("Attachment overwritten") }
        catch { assertError(error, status: 412) }
    }

    func testLegacyProtocolConformerGetsFailClosedAttachmentDefaults() async {
        struct LegacyClient: WebDAVServing {
            func testConnection() async throws { }
            func download() async throws -> WebDAVDownload? { nil }
            func upload(_ data: Data, expectedETag: String?, createOnly: Bool) async throws -> String? { nil }
        }
        let legacy: any WebDAVServing = LegacyClient()
        do { _ = try await legacy.downloadAttachment(id: UUID()); XCTFail("Missing default rejection") }
        catch { guard case WebDAVError.invalidResponse = error else { return XCTFail("Unexpected error") } }
        do { _ = try await legacy.uploadAttachment(Data(), id: UUID()); XCTFail("Missing default rejection") }
        catch { guard case WebDAVError.invalidResponse = error else { return XCTFail("Unexpected error") } }
    }

    private func listResponse(bucket: String = "test-bucket", prefix: String = "") -> Data {
        func escape(_ value: String) -> String {
            value.replacingOccurrences(of: "&", with: "&amp;")
                .replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;")
        }
        return Data(("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
            + "<Name>\(escape(bucket))</Name><Prefix>\(escape(prefix))</Prefix><KeyCount>0</KeyCount>"
            + "<MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>").utf8)
    }

    private func configuration(endpoint: String = "https://s3.invalid") -> S3Configuration {
        S3Configuration(endpoint: endpoint, bucket: "test-bucket", accessKeyID: "testkey", secretAccessKey: "testsecret")
    }

    private func sign(method: String, uri: String, query: String = "", headers: [String: String] = [:], payload: Data = Data()) -> S3Signer.Signature {
        var headers = headers
        headers["host"] = "examplebucket.s3.amazonaws.com"
        headers["x-amz-date"] = "20130524T000000Z"
        headers["x-amz-content-sha256"] = S3Signer.sha256(payload)
        return S3Signer.sign(method: method, canonicalURI: uri, canonicalQuery: query, headers: headers,
                             payloadHash: S3Signer.sha256(payload), accessKeyID: accessKey,
                             secretAccessKey: secretKey, region: "us-east-1", date: date)
    }

    private func assertError(_ error: Error, status: Int, file: StaticString = #filePath, line: UInt = #line) {
        guard let remote = error as? WebDAVError else { return XCTFail("Unexpected error type", file: file, line: line) }
        switch (status, remote) {
        case (401, .authenticationFailed), (403, .accessDenied), (404, .notFound), (409, .conflict),
             (412, .preconditionFailed), (413, .payloadTooLarge), (500, .httpStatus(500)), (307, .unsafeRedirect): break
        default: XCTFail("Unexpected status mapping: \(remote)", file: file, line: line)
        }
    }
}

/// Each fixture has an independent host/handler; parallel tests do not share a mutable global stub.
private final class S3ProtocolFixture {
    let host = UUID().uuidString.lowercased() + ".invalid"
    var endpoint: String { "https://" + host }
    var sessionConfiguration: URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [S3TestURLProtocol.self]
        return config
    }

    func handle(onStop: (() -> Void)? = nil, _ handler: @escaping (URLRequest, S3TestURLProtocol) -> Void) {
        S3TestURLProtocol.set(host: host, handler: handler, onStop: onStop)
    }

    func remove() { S3TestURLProtocol.remove(host: host) }
}

private final class S3TestURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var handlers = [String: (URLRequest, S3TestURLProtocol) -> Void]()
    private static var stops = [String: () -> Void]()
    private var onStop: (() -> Void)?

    static func set(host: String, handler: @escaping (URLRequest, S3TestURLProtocol) -> Void, onStop: (() -> Void)?) {
        lock.lock()
        handlers[host] = handler
        stops[host] = onStop
        lock.unlock()
    }

    static func remove(host: String) {
        lock.lock()
        handlers.removeValue(forKey: host)
        stops.removeValue(forKey: host)
        lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let handler = Self.handlers[request.url?.host ?? ""]
        onStop = Self.stops[request.url?.host ?? ""]
        Self.lock.unlock()
        guard let handler = handler else {
            XCTFail("Unexpected request: no URLProtocol handler")
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        handler(request, self)
    }

    override func stopLoading() { onStop?() }

    func respond(status: Int, headers: [String: String] = [:], chunks: [Data] = []) {
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for chunk in chunks { client?.urlProtocol(self, didLoad: chunk) }
        client?.urlProtocolDidFinishLoading(self)
    }
}

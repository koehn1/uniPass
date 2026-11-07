import Foundation
import XCTest
@testable import uniPass

final class UniPassTests: XCTestCase {
    private var preferences: UserDefaults!
    private var preferencesSuite: String!

    override func setUpWithError() throws {
        try super.setUpWithError()
        preferencesSuite = "UniPassTests-" + UUID().uuidString
        preferences = try XCTUnwrap(UserDefaults(suiteName: preferencesSuite))
        preferences.set(true, forKey: "allowMobileEditing")
    }

    override func tearDownWithError() throws {
        preferences.removePersistentDomain(forName: preferencesSuite)
        preferences = nil
        try super.tearDownWithError()
    }

    func testRFC6238AllAlgorithmsAndTimes() throws {
        let times: [TimeInterval] = [59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000]
        let vectors: [(String, String, [String])] = [
            ("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
             ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]),
            ("SHA256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
             ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]),
            ("SHA512", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
             ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"])
        ]
        for (algorithm, secret, expected) in vectors {
            for (time, code) in zip(times, expected) {
                let uri = "otpauth://totp/RFC6238?secret=\(secret)&algorithm=\(algorithm)&digits=8&period=30"
                XCTAssertEqual(try TOTP.code(secret: uri, date: Date(timeIntervalSince1970: time)), code,
                               "\(algorithm), time=\(time)")
            }
        }
    }

    func testTOTPDefaultsBoundariesAndInvalidInputs() throws {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        XCTAssertEqual(try TOTP.code(secret: secret.lowercased(), date: Date(timeIntervalSince1970: 59)), "287082")
        XCTAssertEqual(TOTP.remaining(secret: secret, date: Date(timeIntervalSince1970: 60)), 30)
        XCTAssertEqual(TOTP.remaining(secret: secret, date: Date(timeIntervalSince1970: 59)), 1)
        let custom = "otpauth://totp/Test?secret=\(secret)&period=60"
        XCTAssertEqual(TOTP.period(secret: custom), 60)
        XCTAssertEqual(TOTP.remaining(secret: custom, date: Date(timeIntervalSince1970: 60)), 60)
        for input in ["", "A", "MZ", "MY=", "ß", "ABC!",
                      "otpauth://hotp/Test?secret=\(secret)",
                      "otpauth://totp/Test?secret=\(secret)&secret=MY",
                      "otpauth://totp/Test?secret=\(secret)&algorithm=MD5",
                      "otpauth://totp/Test?secret=\(secret)&digits=7",
                      "otpauth://totp/Test?secret=\(secret)&period=0"] {
            XCTAssertThrowsError(try TOTP.code(secret: input), "Must reject: \(input)")
        }
        XCTAssertNoThrow(try TOTP.code(secret: "MY======", date: Date(timeIntervalSince1970: 0)))
        for time in [-1.0, Double.nan, Double.infinity] {
            XCTAssertThrowsError(try TOTP.code(secret: secret, date: Date(timeIntervalSince1970: time)))
            XCTAssertEqual(TOTP.remaining(secret: secret, date: Date(timeIntervalSince1970: time)), 0)
        }
    }

    func testPasswordGeneratorBoundariesAndCharacterGroups() throws {
        let groups = [Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), Set("abcdefghijklmnopqrstuvwxyz"),
                      Set("0123456789"), Set("!@#$%^&*()-_=+[]{};:,.<>?/\\|~`\"'")]
        for mask in 1..<16 {
            let enabled = (0..<4).map { mask & (1 << $0) != 0 }
            let selected = groups.enumerated().filter { enabled[$0.offset] }.map { $0.element }
            let allowed = selected.reduce(into: Set<Character>()) { $0.formUnion($1) }
            let password = try PasswordGenerator.generate(length: selected.count,
                uppercase: enabled[0], lowercase: enabled[1], digits: enabled[2], symbols: enabled[3])
            XCTAssertEqual(password.count, selected.count)
            XCTAssertTrue(Set(password).isSubset(of: allowed))
            for group in selected { XCTAssertFalse(Set(password).isDisjoint(with: group)) }
        }
        let longest = try PasswordGenerator.generate(length: 4096, uppercase: false, lowercase: false,
                                                     digits: true, symbols: false)
        XCTAssertEqual(longest.count, 4096)
        XCTAssertTrue(Set(longest).isSubset(of: groups[2]))
        for length in [Int.min, -1, 0, 4097, Int.max] {
            XCTAssertThrowsError(try PasswordGenerator.generate(length: length)) { error in
                guard case PasswordGeneratorError.invalidLength = error else { return XCTFail("\(error)") }
            }
        }
        XCTAssertThrowsError(try PasswordGenerator.generate(length: 3)) { error in
            guard case PasswordGeneratorError.lengthTooShort = error else { return XCTFail("\(error)") }
        }
        XCTAssertThrowsError(try PasswordGenerator.generate(length: 16, uppercase: false,
            lowercase: false, digits: false, symbols: false)) { error in
            guard case PasswordGeneratorError.noCharacterGroups = error else { return XCTFail("\(error)") }
        }
    }

    func testPasswordStrengthIsBoundedAndPenalizesRepetition() {
        XCTAssertEqual(PasswordGenerator.strength("").score, 0)
        XCTAssertLessThanOrEqual(PasswordGenerator.strength(String(repeating: "ab", count: 30)).score, 0.15)
        for password in ["password123", "short-password", "aB7!mN2@pQ9#xR4%", String(repeating: "z", count: 500)] {
            let score = PasswordGenerator.strength(password).score
            XCTAssertTrue(score.isFinite)
            XCTAssertTrue((0...1).contains(score))
        }
    }

    // Five real PBKDF2 calls here; all tamper checks reuse the prepared key.
    func testCryptoRoundTripWrongPasswordTamperingAndIndependentSalts() throws {
        let folder = VaultFolder(name: "Personal")
        let entry = VaultEntry(name: "Example", username: "alice", password: "secret", urls: ["https://example.com"],
            notes: "Multiple lines\nnotes", folderID: folder.id, favorite: true,
            fields: [CustomField(name: "Hidden", value: "value", type: 1)], originalJSON: "{\"extra\":true}",
            createdAt: Date(timeIntervalSince1970: 100), modifiedAt: Date(timeIntervalSince1970: 200))
        let payload = VaultPayload(entries: [entry], folders: [folder])
        let password = try VaultCrypto.passwordData("master-password🔐")
        let first = try VaultCrypto.prepare(payload, password: password)
        let second = try VaultCrypto.prepare(payload, password: password)
        XCTAssertNotEqual(first.header.salt, second.header.salt)
        XCTAssertNotEqual(first.data, second.data)
        for prepared in [first, second] {
            let opened = try VaultCrypto.open(prepared.data, password: password)
            XCTAssertEqual(opened.payload.entries, payload.entries)
            XCTAssertEqual(opened.payload.folders, payload.folders)
        }
        XCTAssertThrowsError(try VaultCrypto.open(first.data, password: Data("wrong".utf8))) { error in
            guard case VaultError.invalidPasswordOrCorruptVault = error else { return XCTFail("\(error)") }
        }
        let envelope = try VaultCrypto.decodeEnvelope(first.data)
        var ciphertext = envelope.ciphertext
        ciphertext[0] ^= 1
        var tag = envelope.tag
        tag[0] ^= 1
        var nonce = envelope.nonce
        nonce[0] ^= 1
        var salt = envelope.header.salt
        salt[0] ^= 1
        let changedHeader = VaultCrypto.Header(version: envelope.header.version, kdf: envelope.header.kdf,
            iterations: envelope.header.iterations, salt: salt, cipher: envelope.header.cipher)
        let mutations = [
            VaultCrypto.Envelope(header: envelope.header, nonce: envelope.nonce, ciphertext: ciphertext, tag: envelope.tag),
            VaultCrypto.Envelope(header: envelope.header, nonce: envelope.nonce, ciphertext: envelope.ciphertext, tag: tag),
            VaultCrypto.Envelope(header: envelope.header, nonce: nonce, ciphertext: envelope.ciphertext, tag: envelope.tag),
            VaultCrypto.Envelope(header: changedHeader, nonce: envelope.nonce, ciphertext: envelope.ciphertext, tag: envelope.tag)
        ]
        for mutation in mutations {
            XCTAssertThrowsError(try VaultCrypto.open(mutation, key: first.key)) { error in
                guard case VaultError.invalidPasswordOrCorruptVault = error else { return XCTFail("\(error)") }
            }
        }
    }

    func testCryptoRejectsInvalidHeadersPasswordsAndPayloadsWithoutKDF() throws {
        XCTAssertThrowsError(try VaultCrypto.passwordData(""))
        XCTAssertEqual(try VaultCrypto.passwordData(String(repeating: "a", count: 4096)).count, 4096)
        XCTAssertThrowsError(try VaultCrypto.passwordData(String(repeating: "é", count: 2049)))
        let header = try VaultCrypto.newHeader()
        for iterations in [0, VaultCrypto.iterations - 1, VaultCrypto.maximumIterations + 1, Int.max] {
            let invalid = VaultCrypto.Header(version: 1, kdf: header.kdf, iterations: iterations,
                                            salt: header.salt, cipher: header.cipher)
            XCTAssertThrowsError(try VaultCrypto.validate(invalid))
        }
        XCTAssertThrowsError(try VaultCrypto.validate(VaultCrypto.Header(version: 2, kdf: header.kdf,
            iterations: header.iterations, salt: header.salt, cipher: header.cipher)))
        XCTAssertThrowsError(try VaultCrypto.decodeEnvelope(Data("{}".utf8)))
        let malformed = VaultCrypto.Envelope(header: header, nonce: Data(count: 11), ciphertext: Data(), tag: Data(count: 16))
        XCTAssertThrowsError(try VaultCrypto.decodeEnvelope(JSONEncoder().encode(malformed)))
        let entry = VaultEntry(name: "duplicate")
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(entries: [entry, entry])))
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(entries: [VaultEntry(folderID: UUID())])))
        let field = CustomField(name: "duplicate")
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(entries: [VaultEntry(fields: [field, field])])))
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(entries: [VaultEntry(fields: [CustomField(type: 4)])])))
        let folder = VaultFolder(name: "duplicate")
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(folders: [folder, folder])))
    }

    func testBitwardenPreservesFoldersFieldsCardAndOriginalJSON() throws {
        let data = Data(Self.bitwardenJSON.utf8)
        let preview = try BitwardenImporter.preview(data: data)
        XCTAssertEqual(preview.itemCount, 2)
        XCTAssertEqual(preview.folderCount, 1)
        XCTAssertEqual(preview.otherTypeCount, 1)
        let imported = try BitwardenImporter.importVault(data: data, into: VaultPayload())
        XCTAssertEqual(imported.importedCount, 2)
        let folder = try XCTUnwrap(imported.payload.folders.first)
        XCTAssertEqual(folder.name, "Personal")
        let login = try XCTUnwrap(imported.payload.entries.first { $0.name == "Login" })
        XCTAssertEqual(login.folderID, folder.id)
        XCTAssertEqual(login.username, "alice")
        XCTAssertEqual(login.password, "secret")
        XCTAssertEqual(login.urls, ["https://example.com", "https://example.org"])
        XCTAssertEqual(login.totp, "MY======")
        XCTAssertEqual(login.notes, "Notes")
        XCTAssertTrue(login.favorite)
        XCTAssertEqual(login.fields.map(\.type), [0, 1, 2, 3])
        XCTAssertEqual(login.fields.map(\.value), ["text", "hidden", "true", "100"])
        XCTAssertEqual(login.createdAt, Date(timeIntervalSince1970: 1_577_836_800))
        let rawLogin = try rawObject(login)
        XCTAssertNotNil(rawLogin["unknownFutureField"])
        XCTAssertNotNil(rawLogin["attachments"])
        let card = try XCTUnwrap(imported.payload.entries.first { $0.name == "Card" })
        XCTAssertEqual(card.folderID, folder.id)
        XCTAssertTrue(card.notes.contains("[Bitwarden Card]"))
        let rawCard = try XCTUnwrap(try rawObject(card)["card"] as? [String: Any])
        XCTAssertEqual(rawCard["number"] as? String, "4111111111111111")
        XCTAssertEqual(rawCard["code"] as? String, "123")
        let source = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let sourceItems = try XCTUnwrap(source["items"] as? [[String: Any]])
        for (entry, original) in zip(imported.payload.entries, sourceItems) {
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: rawObject(entry), options: .sortedKeys),
                           try JSONSerialization.data(withJSONObject: original, options: .sortedKeys))
        }
        let again = try BitwardenImporter.importVault(data: data, into: imported.payload)
        XCTAssertEqual(again.importedCount, 0)
        XCTAssertEqual(again.payload.entries, imported.payload.entries)
        XCTAssertEqual(again.payload.folders, imported.payload.folders)
        let edited = Data(Self.bitwardenJSON.replacingOccurrences(of: "\"password\":\"secret\"", with: "\"password\":\"changed\"").utf8)
        let changed = try BitwardenImporter.importVault(data: edited, into: imported.payload)
        XCTAssertEqual(changed.importedCount, 1)
        XCTAssertEqual(changed.payload.entries.count, 3)
        XCTAssertEqual(Set(changed.payload.entries.map(\.id)).count, 3)
    }

    func testBitwardenRejectsEncryptedWrappersAndMalformedExports() {
        for json in [
            "{\"encrypted\":true,\"items\":[]}",
            "{\"encrypted\":\"false\",\"items\":[]}",
            "{\"encrypted\":0,\"items\":[]}",
            "{\"passwordProtected\":true,\"items\":[]}",
            "{\"salt\":\"abc\",\"items\":[]}",
            "{\"encKeyValidation_DO_NOT_EDIT\":\"abc\",\"items\":[]}",
            "{\"data\":\"encrypted\",\"items\":[]}"
        ] {
            let data = Data(json.utf8)
            XCTAssertThrowsError(try BitwardenImporter.preview(data: data)) { error in
                guard case VaultError.encryptedImport = error else { return XCTFail("\(error)") }
            }
            XCTAssertThrowsError(try BitwardenImporter.importVault(data: data, into: VaultPayload()))
        }
        for json in ["not JSON", "[]", "{}", "{\"items\":[{\"name\":\"bad\",\"type\":1}]}",
                     "{\"items\":[{\"name\":\"bad\",\"type\":true}]}",
                     "{\"items\":[],\"folders\":[{\"id\":\"same\",\"name\":\"a\"},{\"id\":\"same\",\"name\":\"b\"}]}"] {
            XCTAssertThrowsError(try BitwardenImporter.importVault(data: Data(json.utf8), into: VaultPayload()))
        }
    }

    // Two PBKDF2 calls: create and reopen. CRUD writes reuse the session key.
    @MainActor
    func testStoreCRUDLockAndPersistence() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("vault.unipass")
        let store = VaultStore(vaultURL: url, preferences: preferences)
        XCTAssertFalse(store.hasVault)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertThrowsError(try store.save(VaultEntry()))
        try await store.create(password: "store-test-password")
        defer { store.lock() }
        XCTAssertTrue(store.hasVault)
        XCTAssertTrue(store.isUnlocked)
        try store.addFolder(name: "  Work \n")
        let folder = try XCTUnwrap(store.payload.folders.first)
        XCTAssertEqual(folder.name, "Work")
        try store.renameFolder(id: folder.id, name: "Private")
        XCTAssertThrowsError(try store.addFolder(name: " \n"))
        let created = Date(timeIntervalSince1970: 100)
        var entry = VaultEntry(name: "Initial", password: "secret", folderID: folder.id, createdAt: created)
        try store.save(entry)
        entry.name = "Updated"
        entry.createdAt = Date(timeIntervalSince1970: 999)
        try store.save(entry)
        XCTAssertEqual(store.payload.entries.count, 1)
        XCTAssertEqual(store.payload.entries.first?.createdAt, created)
        try store.trash(id: entry.id)
        XCTAssertNotNil(store.payload.entries.first?.deletedAt)
        try store.restore(id: entry.id)
        XCTAssertNil(store.payload.entries.first?.deletedAt)
        let discarded = VaultEntry(name: "Pending deletion")
        try store.save(discarded)
        try store.permanentlyDelete(id: discarded.id)
        XCTAssertThrowsError(try store.restore(id: discarded.id))
        try store.deleteFolder(id: folder.id)
        XCTAssertNil(store.payload.entries.first?.folderID)
        XCTAssertTrue(store.payload.folders.isEmpty)
        let snapshot = store.payload.entries
        let ciphertext = try Data(contentsOf: url)
        store.lock()
        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.hasVault)
        XCTAssertTrue(store.payload.entries.isEmpty)
        XCTAssertTrue(store.payload.folders.isEmpty)
        XCTAssertThrowsError(try store.encryptedData())
        XCTAssertThrowsError(try store.save(entry))
        XCTAssertThrowsError(try store.importBitwarden(data: Data(Self.bitwardenJSON.utf8)))
        XCTAssertEqual(try Data(contentsOf: url), ciphertext)
        let reopened = VaultStore(vaultURL: url, preferences: preferences)
        XCTAssertTrue(reopened.hasVault)
        XCTAssertFalse(reopened.isUnlocked)
        try await reopened.unlock(password: "store-test-password")
        defer { reopened.lock() }
        XCTAssertEqual(reopened.payload.entries, snapshot)
        XCTAssertTrue(reopened.payload.folders.isEmpty)
    }

    // One PBKDF2 call. A directory at the destination forces atomic rename to fail,
    // including when the test process has permission to ignore chmod restrictions.
    @MainActor
    func testFailedStoreWritesLeaveMemoryAndOriginalCiphertextUnchanged() async throws {
        let manager = FileManager.default
        let directory = try makeTemporaryDirectory()
        defer { try? manager.removeItem(at: directory) }
        let url = directory.appendingPathComponent("vault.unipass")
        let backup = directory.appendingPathComponent("original.enc")
        let store = VaultStore(vaultURL: url, preferences: preferences)
        try await store.create(password: "write-failure-test")
        defer { store.lock() }
        try store.addFolder(name: "Retained folder")
        let folder = try XCTUnwrap(store.payload.folders.first)
        let entry = VaultEntry(name: "Retained entry", folderID: folder.id)
        try store.save(entry)
        let entries = store.payload.entries
        let folders = store.payload.folders
        let original = try Data(contentsOf: url)
        try manager.moveItem(at: url, to: backup)
        try manager.createDirectory(at: url, withIntermediateDirectories: false)
        var changed = entry
        changed.name = "Must not commit"
        let operations: [() throws -> Void] = [
            { try store.save(changed) },
            { try store.save(VaultEntry(name: "Must not add")) },
            { try store.addFolder(name: "Must not add") },
            { try store.renameFolder(id: folder.id, name: "Must not rename") },
            { try store.deleteFolder(id: folder.id) },
            { try store.trash(id: entry.id) },
            { try store.permanentlyDelete(id: entry.id) },
            { _ = try store.importBitwarden(data: Data(Self.bitwardenJSON.utf8)) }
        ]
        for operation in operations {
            XCTAssertThrowsError(try operation())
            XCTAssertEqual(store.payload.entries, entries)
            XCTAssertEqual(store.payload.folders, folders)
            XCTAssertTrue(store.isUnlocked)
            XCTAssertEqual(try Data(contentsOf: backup), original)
        }
        XCTAssertEqual(try manager.contentsOfDirectory(atPath: url.path), [])
        let remaining = try manager.contentsOfDirectory(atPath: directory.path)
        XCTAssertFalse(remaining.contains { $0.hasPrefix(".unipass-") })
        try manager.removeItem(at: url)
        try manager.moveItem(at: backup, to: url)
        try store.save(changed)
        XCTAssertEqual(store.payload.entries.first?.name, changed.name)
        XCTAssertNotEqual(try Data(contentsOf: url), original)
    }

    func testWebDAVRejectsUnsafeConfigurationWithoutNetwork() throws {
        XCTAssertNoThrow(try WebDAVClient(configuration: WebDAVConfiguration(serverURL: "https://example.invalid/existing/")))
        for address in ["", "ftp://example.invalid/vault", " https://example.invalid/",
                        "https://user:password@example.invalid/", "https://example.invalid/?query=1",
                        "https://example.invalid/#fragment", "https://example.invalid:0/",
                        "https://example.invalid:65536/"] {
            XCTAssertThrowsError(try WebDAVClient(configuration: WebDAVConfiguration(serverURL: address)))
        }
        XCTAssertThrowsError(try WebDAVClient(configuration: WebDAVConfiguration(serverURL: "http://example.invalid/"))) { error in
            guard case WebDAVError.insecureHTTP = error else { return XCTFail("\(error)") }
        }
        for (username, password) in [("user:name", "pass"), ("user\n", "pass"), ("user", "pass\r")] {
            XCTAssertThrowsError(try WebDAVClient(configuration: WebDAVConfiguration(
                serverURL: "https://example.invalid/", username: username, password: password))) { error in
                guard case WebDAVError.invalidCredentials = error else { return XCTFail("\(error)") }
            }
        }
    }

    func testWebDAVUploadRequiresSafePreconditionsBeforeNetwork() async throws {
        let client = try WebDAVClient(configuration: WebDAVConfiguration(serverURL: "https://example.invalid/"))
        let cases: [(String?, Bool)] = [(nil, false), ("", false), ("W/\"weak\"", false),
            ("*", false), ("unquoted", false), ("\"one\", \"two\"", false),
            ("\"bad\r\nvalue\"", false), ("\"existing\"", true)]
        for (etag, createOnly) in cases {
            do {
                _ = try await client.upload(Data(), expectedETag: etag, createOnly: createOnly)
                XCTFail("Unsafe upload must fail before contacting the network")
            } catch {
                guard let error = error as? WebDAVError else { XCTFail("\(error)"); continue }
                switch error {
                case .missingETag: XCTAssertTrue(etag == nil || etag == "")
                case .invalidETag: XCTAssertFalse(createOnly)
                case .conflictingConditions: XCTAssertTrue(createOnly)
                default: XCTFail("Expected local validation, got \(error)")
                }
            }
        }
    }

    @MainActor
    func testTwoDeviceSyncPushPullConflictAndBackups() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = VaultStore(vaultURL: directory.appendingPathComponent("first/vault.unipass"), preferences: preferences)
        let second = VaultStore(vaultURL: directory.appendingPathComponent("second/vault.unipass"), preferences: preferences)
        defer { first.lock(); second.lock() }
        try await first.create(password: "same-master-password")
        try await second.create(password: "same-master-password")
        let entry = VaultEntry(name: "Initial entry", password: "initial")
        try first.save(entry)
        let server = MemoryWebDAV()
        let suiteA = "UniPassSyncTests-A-" + UUID().uuidString
        let suiteB = "UniPassSyncTests-B-" + UUID().uuidString
        let defaultsA = try XCTUnwrap(UserDefaults(suiteName: suiteA))
        let defaultsB = try XCTUnwrap(UserDefaults(suiteName: suiteB))
        defer { defaultsA.removePersistentDomain(forName: suiteA); defaultsB.removePersistentDomain(forName: suiteB) }
        let syncA = SyncCoordinator(defaults: defaultsA, makeClient: { _ in server })
        let syncB = SyncCoordinator(defaults: defaultsB, makeClient: { _ in server })
        syncA.configuration.serverURL = "https://test.invalid/vault/"
        syncB.configuration = syncA.configuration

        await syncA.synchronize(store: first)
        XCTAssertNotNil(syncA.lastSync)
        let uploaded = await server.bytes()
        XCTAssertEqual(uploaded, try Data(contentsOf: first.vaultURL))
        await syncB.synchronize(store: second)
        XCTAssertEqual(second.payload.entries, first.payload.entries)
        XCTAssertEqual(try Data(contentsOf: second.vaultURL), uploaded)

        var changed = entry; changed.password = "first-device-change"
        try first.save(changed)
        await syncA.synchronize(store: first)
        await syncB.synchronize(store: second)
        XCTAssertEqual(second.payload.entries, first.payload.entries)
        let repeated = await server.uploadCount()
        await syncA.synchronize(store: first)
        await syncB.synchronize(store: second)
        let afterNoChange = await server.uploadCount()
        XCTAssertEqual(repeated, afterNoChange, "Stable ciphertext must not create unnecessary uploads")

        changed.password = "first-offline-change"; try first.save(changed)
        var other = changed; other.password = "second-offline-change"; try second.save(other)
        await syncA.synchronize(store: first)
        let firstRemote = await server.bytes()
        await syncB.synchronize(store: second)
        XCTAssertTrue(syncB.hasConflict)
        XCTAssertEqual(second.payload.entries.first?.password, "second-offline-change")
        let unchangedRemote = await server.bytes()
        XCTAssertEqual(unchangedRemote, firstRemote)
        await syncB.resolve(useRemote: false, store: second)
        XCTAssertFalse(syncB.hasConflict)
        let resolved = await server.bytes()
        XCTAssertEqual(resolved, try Data(contentsOf: second.vaultURL))
        let backupFolder = second.vaultURL.deletingLastPathComponent().appendingPathComponent("Sync Backups")
        let backupFiles = try FileManager.default.contentsOfDirectory(at: backupFolder, includingPropertiesForKeys: nil)
        XCTAssertTrue(try backupFiles.contains {
            try VaultBackup.decode(Data(contentsOf: $0)).vault == firstRemote
        })
        await syncA.synchronize(store: first)
        XCTAssertEqual(first.payload.entries.first?.password, "second-offline-change")

        // A remote disappearing after a successful sync must not resurrect data.
        await server.removeRemote()
        await syncA.synchronize(store: first)
        let deletedRemote = await server.bytes()
        XCTAssertNil(deletedRemote)
        XCTAssertTrue(syncA.message?.contains("no longer exists") == true)
    }

    @MainActor
    func testSyncDownloadPreservesPortableBackupIncludingOldLocalAttachments() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        let store = fixture.store
        defer { store.lock() }
        let oldVault = try store.encryptedSnapshot()
        let oldBlob = try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL)
        let server = MemoryWebDAV()
        let sync = SyncCoordinator(defaults: preferences, makeClient: { _ in server })
        sync.configuration.serverURL = "https://test.invalid/portable-backup/"
        await sync.synchronize(store: store)
        XCTAssertNotNil(sync.lastSync)
        let initialDownload = try await server.download()
        let initialRemote = try XCTUnwrap(initialDownload)
        XCTAssertEqual(initialRemote.data, oldVault)

        // Change only the remote after establishing a baseline, exercising the
        // automatic download branch rather than explicit conflict resolution.
        let remoteEntry = VaultEntry(name: "remote replacement without old attachment")
        let remote = try VaultCrypto.prepare(VaultPayload(entries: [remoteEntry]),
            password: VaultCrypto.passwordData("complete-backup-password")).data
        _ = try await server.upload(remote, expectedETag: initialRemote.etag, createOnly: false)
        let uploadsBeforeDownload = await server.uploadCount()
        await sync.synchronize(store: store)
        XCTAssertFalse(sync.hasConflict)
        XCTAssertTrue(sync.message?.contains("Remote changes were downloaded") == true, sync.message ?? "Missing sync message")
        XCTAssertEqual(try store.encryptedSnapshot(), remote)
        XCTAssertEqual(store.payload.entries, [remoteEntry])
        let uploadsAfterDownload = await server.uploadCount()
        XCTAssertEqual(uploadsAfterDownload, uploadsBeforeDownload)
        let records = try BackupFiles.records(vaultURL: store.vaultURL)
        XCTAssertEqual(records.count, 1)
        let record = try XCTUnwrap(records.first)
        let saved = try VaultBackup.decode(BackupFiles.read(record.url, maximumBytes: VaultBackup.maximumBytes))
        XCTAssertEqual(saved.vault, oldVault)
        XCTAssertEqual(saved.attachments, [fixture.attachment.id: oldBlob])

        let portableURL = directory.appendingPathComponent("portable-old-version.enc")
        try FileManager.default.copyItem(at: record.url, to: portableURL)
        store.lock()
        try FileManager.default.removeItem(at: store.vaultURL.deletingLastPathComponent())
        let recovered = VaultStore(vaultURL: directory.appendingPathComponent("recovered/vault.unipass"), preferences: preferences)
        XCTAssertFalse(recovered.hasVault)
        let backup = try BackupFiles.readScoped(portableURL, maximumBytes: VaultBackup.maximumBytes)
        try await recovered.restoreBackup(data: backup, password: "complete-backup-password")
        defer { recovered.lock() }
        XCTAssertEqual(try recovered.encryptedSnapshot(), oldVault)
        XCTAssertEqual(try recovered.attachmentData(entryID: fixture.entry.id, attachmentID: fixture.attachment.id), fixture.bytes)
    }

    @MainActor
    func testSyncKeepLocalDoesNotUploadWhenRemoteAttachmentBackupIsIncomplete() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let local = try await makeBackupFixture(at: directory.appendingPathComponent("local"))
        let remote = try await makeBackupFixture(at: directory.appendingPathComponent("remote"))
        defer { local.store.lock(); remote.store.lock() }
        let localVault = try local.store.encryptedSnapshot()
        let localBlob = try VaultAttachmentDisk.readBlob(local.attachment.id, vault: local.store.vaultURL)
        let remoteVault = try remote.store.encryptedSnapshot()
        XCTAssertNotEqual(local.attachment.id, remote.attachment.id)
        XCTAssertThrowsError(try VaultAttachmentDisk.readBlob(remote.attachment.id, vault: local.store.vaultURL)) { error in
            guard case VaultError.attachmentNotFound = error else { return XCTFail("\(error)") }
        }
        let server = MemoryWebDAV()
        _ = try await server.upload(remoteVault, expectedETag: nil, createOnly: true)
        let sync = SyncCoordinator(defaults: preferences, makeClient: { _ in server })
        sync.configuration.serverURL = "https://test.invalid/incomplete-remote-backup/"
        await sync.synchronize(store: local.store)
        XCTAssertTrue(sync.hasConflict)
        XCTAssertNil(sync.lastSync)
        let beforeDownload = try await server.download()
        let before = try XCTUnwrap(beforeDownload)
        let uploadsBefore = await server.uploadCount()

        await sync.resolve(useRemote: false, store: local.store)
        let afterDownload = try await server.download()
        let after = try XCTUnwrap(afterDownload)
        let uploadsAfter = await server.uploadCount()
        XCTAssertEqual(uploadsAfter, uploadsBefore, "Do not upload until the replaced remote has a complete backup")
        XCTAssertEqual(after.data, before.data)
        XCTAssertEqual(after.etag, before.etag)
        XCTAssertEqual(after.data, remoteVault)

        XCTAssertTrue(sync.message?.contains("attachment") == true && sync.message?.contains("missing") == true)
        XCTAssertFalse(sync.busy)
        XCTAssertNil(sync.lastSync, "Failed preservation must not establish a synchronization baseline")
        XCTAssertEqual(try Data(contentsOf: local.store.vaultURL), localVault)
        XCTAssertEqual(try local.store.encryptedSnapshot(), localVault)
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(local.attachment.id, vault: local.store.vaultURL), localBlob)
        XCTAssertTrue(try BackupFiles.records(vaultURL: local.store.vaultURL).isEmpty, "No partial backup may be published")
    }

    @MainActor
    func testSyncRejectsLocalChangesAndLateResultsAfterLock() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = VaultStore(vaultURL: directory.appendingPathComponent("vault.unipass"), preferences: preferences)
        try await store.create(password: "sync-race-password")
        defer { store.lock() }
        let entry = VaultEntry(name: "before")
        try store.save(entry)
        let server = MemoryWebDAV()
        let suite = "UniPassSyncRace-" + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let sync = SyncCoordinator(defaults: defaults, makeClient: { _ in server })
        sync.configuration.serverURL = "https://test.invalid/vault/"
        await server.interceptNextDownload {
            var changed = entry; changed.name = "edited-during-network"
            do { try store.save(changed) } catch { XCTFail(error.localizedDescription) }
        }
        await sync.synchronize(store: store)
        XCTAssertEqual(store.payload.entries.first?.name, "edited-during-network")
        let uploads = await server.uploadCount()
        XCTAssertEqual(uploads, 0)
        XCTAssertTrue(sync.message?.contains("changed") == true)
        await server.interceptNextDownload { store.lock(); sync.cancelPending() }
        await sync.synchronize(store: store)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.payload.entries.isEmpty)
        let afterLock = await server.uploadCount()
        XCTAssertEqual(afterLock, 0)
        XCTAssertNil(sync.lastSync)
    }

    @MainActor
    func testInitialBackupRestoreAuthenticatesAndDoesNotOverwriteExistingVault() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = VaultStore(vaultURL: directory.appendingPathComponent("source.unipass"), preferences: preferences)
        try await source.create(password: "backup-test-password")
        let entry = VaultEntry(name: "backup item", password: "kept")
        try source.save(entry)
        let encrypted = try Data(contentsOf: source.vaultURL)
        source.lock()
        preferences.removeObject(forKey: "allowMobileEditing")
        let target = VaultStore(vaultURL: directory.appendingPathComponent("target.unipass"), preferences: preferences)
        XCTAssertFalse(target.allowMobileEditing)
        do {
            try await target.restoreBackup(data: encrypted, password: "wrong")
            XCTFail("Wrong password must not create a vault")
        } catch { }
        XCTAssertFalse(target.hasVault)
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.vaultURL.path))
        try await target.restoreBackup(data: encrypted, password: "backup-test-password")
        defer { target.lock() }
        XCTAssertEqual(target.payload.entries.first?.id, entry.id)
        XCTAssertEqual(try Data(contentsOf: target.vaultURL), encrypted)
        XCTAssertFalse(target.allowMobileEditing)
        XCTAssertNil(preferences.object(forKey: "allowMobileEditing"))
        #if !targetEnvironment(macCatalyst)
        XCTAssertThrowsError(try target.save(VaultEntry(name: "still read only"))) { error in
            guard case VaultError.mobileEditingDisabled = error else { return XCTFail("\(error)") }
        }
        #endif
        do {
            try await target.restoreBackup(data: encrypted, password: "backup-test-password")
            XCTFail("Must not overwrite an existing vault")
        } catch { }
        XCTAssertEqual(try Data(contentsOf: target.vaultURL), encrypted)
    }

    @MainActor
    func testCustomDirectoryCopyBookmarkAndReopenPreserveSource() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let suite = "UniPassLocation-" + UUID().uuidString
        let preferences = try XCTUnwrap(UserDefaults(suiteName: suite))
        preferences.set(true, forKey: "allowMobileEditing")
        defer { preferences.removePersistentDomain(forName: suite) }
        let sourceURL = directory.appendingPathComponent("local/vault.unipass")
        let cloud = directory.appendingPathComponent("cloud", isDirectory: true)
        try FileManager.default.createDirectory(at: cloud, withIntermediateDirectories: true)
        let store = VaultStore(vaultURL: sourceURL, preferences: preferences)
        try await store.create(password: "custom-location-password")
        let entry = VaultEntry(name: "cloud item", password: "encrypted only")
        try store.save(entry)
        let attachmentFile = directory.appendingPathComponent("copied.txt")
        let attachmentBytes = Data("copy attachments too".utf8)
        try attachmentBytes.write(to: attachmentFile)
        try store.addAttachment(entryID: entry.id, from: attachmentFile)
        let attachment = try XCTUnwrap(store.payload.entries.first?.attachments.first)
        let original = try Data(contentsOf: sourceURL)
        let unsafeDocuments = cloud.appendingPathComponent("documents")
        try FileManager.default.createSymbolicLink(at: unsafeDocuments,
            withDestinationURL: sourceURL.deletingLastPathComponent().appendingPathComponent("documents"))
        XCTAssertThrowsError(try store.copyToDirectory(cloud))
        XCTAssertEqual(store.vaultURL, sourceURL)
        XCTAssertFalse(FileManager.default.fileExists(atPath: cloud.appendingPathComponent("vault.unipass").path))
        XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id), attachmentBytes)
        try FileManager.default.removeItem(at: unsafeDocuments)
        try store.copyToDirectory(cloud)
        XCTAssertFalse(store.isUnlocked)
        XCTAssertTrue(store.usesCustomLocation)
        XCTAssertEqual(store.vaultURL, cloud.appendingPathComponent("vault.unipass"))
        XCTAssertEqual(try Data(contentsOf: sourceURL), original, "Migration must retain the source")
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), original)
        let restarted = VaultStore(preferences: preferences)
        XCTAssertEqual(restarted.vaultURL, store.vaultURL)
        XCTAssertNil(restarted.locationError)
        try await restarted.unlock(password: "custom-location-password")
        XCTAssertEqual(restarted.payload.entries.first?.id, entry.id)
        XCTAssertEqual(try restarted.attachmentData(entryID: entry.id, attachmentID: attachment.id), attachmentBytes)
        XCTAssertTrue(FileManager.default.fileExists(atPath: sourceURL.deletingLastPathComponent()
            .appendingPathComponent("documents").appendingPathComponent(VaultAttachmentDisk.blobName(attachment.id)).path))
        restarted.lock()
        try store.useDefaultDirectory()
        XCTAssertFalse(store.usesCustomLocation)
        XCTAssertEqual(store.vaultURL, sourceURL)
        XCTAssertNil(preferences.data(forKey: "uniPass.vault.directory.v1"))
    }

    @MainActor
    func testCustomDirectoryNeverOverwritesAnExistingDestination() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let cloud = directory.appendingPathComponent("cloud", isDirectory: true)
        try FileManager.default.createDirectory(at: cloud, withIntermediateDirectories: true)
        let existing = Data("do-not-overwrite".utf8)
        let destination = cloud.appendingPathComponent("vault.unipass")
        try existing.write(to: destination)
        let store = VaultStore(vaultURL: directory.appendingPathComponent("local.unipass"), preferences: preferences)
        try await store.create(password: "keep-existing-password")
        defer { store.lock() }
        let source = store.vaultURL
        XCTAssertThrowsError(try store.copyToDirectory(cloud))
        XCTAssertTrue(store.isUnlocked)
        XCTAssertEqual(store.vaultURL, source)
        XCTAssertEqual(try Data(contentsOf: destination), existing)
        XCTAssertThrowsError(try store.openDirectory(cloud))
        XCTAssertEqual(store.vaultURL, source)
    }

    @MainActor
    func testExternalReplacementRejectsStaleSaveAndPreservesSnapshot() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("vault.unipass")
        let first = VaultStore(vaultURL: url, preferences: preferences)
        try await first.create(password: "external-change-password")
        var entry = VaultEntry(name: "original", password: "original password")
        try first.save(entry)
        let original = try Data(contentsOf: url)
        let second = VaultStore(vaultURL: url, preferences: preferences)
        try await second.unlock(password: "external-change-password")
        entry.name = "new version from other device"
        try second.save(entry)
        second.lock()
        let newest = try Data(contentsOf: url)
        var stale = entry; stale.name = "stale edit must not overwrite"
        XCTAssertThrowsError(try first.save(stale)) { error in
            guard case VaultError.externalChange = error else { return XCTFail("\(error)") }
        }
        XCTAssertNotNil(first.externalChangeMessage)
        XCTAssertEqual(first.payload.entries.first?.name, "original")
        XCTAssertEqual(try Data(contentsOf: url), newest)
        let backups = try FileManager.default.contentsOfDirectory(at: first.backupDirectory, includingPropertiesForKeys: nil)
        XCTAssertTrue(try backups.contains { try Data(contentsOf: $0) == original })
        first.lock()
        try await first.unlock(password: "external-change-password")
        XCTAssertEqual(first.payload.entries.first?.name, entry.name)
        XCTAssertNil(first.externalChangeMessage)
        first.lock()
    }

    @MainActor
    func testExternalRefreshAndMissingCloudFileCannotCreateEmptyVault() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let suite = "UniPassMissingCloud-" + UUID().uuidString
        let preferences = try XCTUnwrap(UserDefaults(suiteName: suite))
        preferences.set(true, forKey: "allowMobileEditing")
        defer { preferences.removePersistentDomain(forName: suite) }
        let cloud = directory.appendingPathComponent("cloud", isDirectory: true)
        try FileManager.default.createDirectory(at: cloud, withIntermediateDirectories: true)
        let store = VaultStore(vaultURL: directory.appendingPathComponent("local.unipass"), preferences: preferences)
        try await store.create(password: "missing-cloud-password")
        try store.copyToDirectory(cloud)
        try await store.unlock(password: "missing-cloud-password")
        let valid = try Data(contentsOf: store.vaultURL)
        try (valid + Data("\n".utf8)).write(to: store.vaultURL, options: .atomic)
        await store.checkForExternalChanges()
        XCTAssertNotNil(store.externalChangeMessage)
        XCTAssertTrue(store.isUnlocked, "Do not silently discard an open editor")
        store.lock()
        try FileManager.default.removeItem(at: store.vaultURL)
        do { try await store.unlock(password: "missing-cloud-password"); XCTFail("Missing file must not open") } catch { }
        XCTAssertTrue(store.hasVault, "Missing cloud file must not show the create-empty-vault flow")
        do { try await store.create(password: "missing-cloud-password"); XCTFail("Must not create an empty cloud vault") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.vaultURL.path))
    }

    func testLegacyPayloadWithoutAttachmentsDecodesAndRoundTrips() throws {
        let entry = VaultEntry(name: "Old vault", originalJSON: "{\"retained\":true}")
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with:
            JSONEncoder().encode(VaultPayload(entries: [entry]))) as? [String: Any])
        var entries = try XCTUnwrap(object["entries"] as? [[String: Any]])
        entries[0].removeValue(forKey: "attachments")
        object["entries"] = entries
        let legacy = try JSONDecoder().decode(VaultPayload.self,
            from: JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(legacy.entries, [entry])
        XCTAssertEqual(legacy.entries.first?.attachments, [])
        let prepared = try VaultCrypto.prepare(legacy, password: Data("legacy-password".utf8))
        let opened = try VaultCrypto.open(VaultCrypto.decodeEnvelope(prepared.data), key: prepared.key)
        XCTAssertEqual(opened.payload.entries, [entry])
    }

    @MainActor
    func testAttachmentEncryptedCRUDPasswordChangeAndStaleEditor() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = VaultStore(vaultURL: directory.appendingPathComponent("vault.unipass"), preferences: preferences)
        try await store.create(password: "attachment-password")
        defer { store.lock() }
        let entry = VaultEntry(name: "Attachment", originalJSON: "{\"retained\":true}")
        try store.save(entry)
        let source = directory.appendingPathComponent("secret.txt")
        let plaintext = Data("private attachment\nnot plaintext on disk".utf8)
        try plaintext.write(to: source)
        try store.addAttachment(entryID: entry.id, from: source)
        let attachment = try XCTUnwrap(store.payload.entries.first?.attachments.first)
        XCTAssertEqual(attachment.fileName, "secret.txt")
        XCTAssertEqual(attachment.byteCount, Int64(plaintext.count))
        XCTAssertEqual(attachment.key.count, 32)
        let blob = directory.appendingPathComponent("documents").appendingPathComponent(VaultAttachmentDisk.blobName(attachment.id))
        let encrypted = try Data(contentsOf: blob)
        XCTAssertEqual(encrypted.count, plaintext.count + 28)
        XCTAssertNil(encrypted.range(of: plaintext))
        XCTAssertNil(try Data(contentsOf: store.vaultURL).range(of: plaintext))
        XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id), plaintext)
        XCTAssertThrowsError(try VaultCrypto.openAttachment(encrypted, entryID: UUID(), attachment: attachment))
        var damaged = encrypted
        damaged[damaged.count - 1] ^= 1
        XCTAssertThrowsError(try VaultCrypto.openAttachment(damaged, entryID: entry.id, attachment: attachment))
        try store.save(entry) // Stale editor must not erase attachments.
        XCTAssertEqual(store.payload.entries.first?.attachments, [attachment])
        try store.removeOriginalJSON(id: entry.id)
        XCTAssertNil(store.payload.entries.first?.originalJSON)
        try store.trash(id: entry.id)
        XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id), plaintext)
        try store.restore(id: entry.id)
        try await store.changePassword(current: "attachment-password", new: "new-attachment-password")
        XCTAssertEqual(try Data(contentsOf: blob), encrypted, "Changing master password must not re-encrypt blobs")
        store.lock()
        XCTAssertThrowsError(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id))
        try await store.unlock(password: "new-attachment-password")
        XCTAssertEqual(store.payload.entries.first?.attachments.first?.key, attachment.key)
        XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id), plaintext)
        try store.removeAttachment(entryID: entry.id, attachmentID: attachment.id)
        XCTAssertTrue(store.payload.entries.first?.attachments.isEmpty == true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: blob.path))
        XCTAssertThrowsError(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id))
        try store.addAttachment(entryID: entry.id, from: source)
        let second = try XCTUnwrap(store.payload.entries.first?.attachments.first)
        XCTAssertNotEqual(second.key, attachment.key)
        try store.permanentlyDelete(id: entry.id)
        XCTAssertFalse(FileManager.default.fileExists(atPath: blob.deletingLastPathComponent()
            .appendingPathComponent(VaultAttachmentDisk.blobName(second.id)).path))
    }

    @MainActor
    func testAttachmentPathsLimitsAndFailedCommitKeepExistingData() async throws {
        let manager = FileManager.default
        let directory = try makeTemporaryDirectory()
        defer { try? manager.removeItem(at: directory) }
        let store = VaultStore(vaultURL: directory.appendingPathComponent("vault.unipass"), preferences: preferences)
        try await store.create(password: "attachment-failure-password")
        defer { store.lock() }
        let entry = VaultEntry(name: "Retained")
        try store.save(entry)
        let source = directory.appendingPathComponent("source.txt")
        let plaintext = Data("keep this file".utf8)
        try plaintext.write(to: source)
        let link = directory.appendingPathComponent("link.txt")
        try manager.createSymbolicLink(at: link, withDestinationURL: source)
        XCTAssertThrowsError(try store.addAttachment(entryID: entry.id, from: link))
        let linkedDirectory = directory.appendingPathComponent("linked")
        try manager.createSymbolicLink(at: linkedDirectory, withDestinationURL: directory)
        XCTAssertThrowsError(try store.addAttachment(entryID: entry.id, from: linkedDirectory.appendingPathComponent("source.txt")))
        let traversal = URL(fileURLWithPath: directory.path + "/../" + directory.lastPathComponent + "/source.txt")
        XCTAssertThrowsError(try store.addAttachment(entryID: entry.id, from: traversal))
        let huge = directory.appendingPathComponent("huge.bin")
        XCTAssertTrue(manager.createFile(atPath: huge.path, contents: nil))
        let handle = try FileHandle(forWritingTo: huge)
        try handle.truncate(atOffset: UInt64(VaultCrypto.maximumAttachmentBytes + 1))
        try handle.close()
        XCTAssertThrowsError(try store.addAttachment(entryID: entry.id, from: huge))
        try store.addAttachment(entryID: entry.id, from: source)
        let attachment = try XCTUnwrap(store.payload.entries.first?.attachments.first)
        let before = store.payload.entries
        let original = try Data(contentsOf: store.vaultURL)
        let held = directory.appendingPathComponent("held.unipass")
        try manager.moveItem(at: store.vaultURL, to: held)
        try manager.createDirectory(at: store.vaultURL, withIntermediateDirectories: false)
        XCTAssertThrowsError(try store.removeAttachment(entryID: entry.id, attachmentID: attachment.id))
        XCTAssertThrowsError(try store.addAttachment(entryID: entry.id, from: source))
        XCTAssertThrowsError(try store.permanentlyDelete(id: entry.id))
        XCTAssertEqual(store.payload.entries, before)
        XCTAssertEqual(try Data(contentsOf: held), original)
        let documents = directory.appendingPathComponent("documents")
        XCTAssertEqual(try manager.contentsOfDirectory(atPath: documents.path), [VaultAttachmentDisk.blobName(attachment.id)])
        try manager.removeItem(at: store.vaultURL)
        try manager.moveItem(at: held, to: store.vaultURL)
        XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id), plaintext)
        let blob = documents.appendingPathComponent(VaultAttachmentDisk.blobName(attachment.id))
        let heldBlob = directory.appendingPathComponent("held.enc")
        try manager.moveItem(at: blob, to: heldBlob)
        try manager.createSymbolicLink(at: blob, withDestinationURL: heldBlob)
        XCTAssertThrowsError(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id))
        XCTAssertEqual(try Data(contentsOf: heldBlob).count, plaintext.count + 28)
    }

    @MainActor
    func testOfficialBitwardenFilesImportWithoutJSONAttachmentMetadataAndDedupe() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = VaultStore(vaultURL: directory.appendingPathComponent("vault.unipass"), preferences: preferences)
        try await store.create(password: "bitwarden-files-password")
        defer { store.lock() }
        let data = Data(#"{"encrypted":false,"items":[{"id":"cipher-id","name":"Example","type":1,"login":{}}]}"#.utf8)
        let plaintext = Data("actual exported attachment".utf8)
        for folder in ["cipher-id", "Example"] {
            let root = directory.appendingPathComponent(folder + "-export")
            let files = root.appendingPathComponent("attachments").appendingPathComponent(folder)
            try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
            try data.write(to: root.appendingPathComponent("data.json"))
            try plaintext.write(to: files.appendingPathComponent("example.txt"))
            let count = try store.importBitwarden(data: data, attachmentsDirectory: root)
            XCTAssertEqual(count, folder == "cipher-id" ? 1 : 0)
            XCTAssertEqual(store.payload.entries.count, 1)
            let entry = try XCTUnwrap(store.payload.entries.first)
            XCTAssertEqual(entry.attachments.count, 1)
            let attachment = try XCTUnwrap(entry.attachments.first)
            XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id), plaintext)
            XCTAssertEqual(try store.importBitwarden(data: data, attachmentsDirectory: root), 0)
            XCTAssertEqual(store.payload.entries.first?.attachments, entry.attachments)
            try Data("different content".utf8).write(to: files.appendingPathComponent("example.txt"))
            let snapshot = try store.encryptedSnapshot()
            XCTAssertThrowsError(try store.importBitwarden(data: data, attachmentsDirectory: root))
            XCTAssertEqual(try store.encryptedSnapshot(), snapshot)
            XCTAssertEqual(store.payload.entries.first?.attachments, entry.attachments)
        }
    }

    @MainActor
    func testBitwardenModernSanitizedNamesMetadataAndAttachmentValidation() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = VaultStore(vaultURL: directory.appendingPathComponent("vault.unipass"), preferences: preferences)
        try await store.create(password: "sanitized-import-password")
        defer { store.lock() }
        let root = directory.appendingPathComponent("export")
        let files = root.appendingPathComponent("attachments/Name_with_characters")
        try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
        // Match the current official exporter: collapsed directory underscores,
        // counters keyed by sanitized filenames, and removal of stem dots.
        let data = Data(#"{"items":[{"id":"cipher","name":"Name/\\\\><:\"|?*__with__characters","type":1,"login":{},"attachments":[{"fileName":"a:b.txt"},{"fileName":"a?b.txt"},{"fileName":"a?b.txt"},{"fileName":"report.v1.final.txt"},{"fileName":"literal_1.txt"},{"fileName":"plain"}]}]}"#.utf8)
        try data.write(to: root.appendingPathComponent("data.json"))
        let actualNames = ["a_b.txt", "a_b_1.txt", "a_b_2.txt", "reportv1final.txt", "literal_1.txt", "plain"]
        for name in actualNames {
            try Data(("metadata file " + name).utf8).write(to: files.appendingPathComponent(name))
        }
        XCTAssertEqual(try store.importBitwarden(data: data, attachmentsDirectory: root), 1)
        let entry = try XCTUnwrap(store.payload.entries.first)
        XCTAssertEqual(entry.attachments.map(\.fileName).sorted(), actualNames.sorted())
        for attachment in entry.attachments {
            XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id),
                Data(("metadata file " + attachment.fileName).utf8))
        }
        let attachment = try XCTUnwrap(entry.attachments.first)
        let rawAttachments = try XCTUnwrap(try rawObject(entry)["attachments"] as? [[String: Any]])
        XCTAssertEqual(rawAttachments.first?["fileName"] as? String, "a:b.txt")
        var invalid = entry
        invalid.attachments[0].key = Data(count: 31)
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(entries: [invalid])))
        invalid = entry
        invalid.attachments[0].byteCount = -1
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(entries: [invalid])))
        invalid = entry
        invalid.attachments[0].fileName = "../escape"
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(entries: [invalid])))
        invalid = entry
        invalid.attachments.append(attachment)
        XCTAssertThrowsError(try VaultCrypto.validatePayload(VaultPayload(entries: [invalid])))
        let snapshot = try store.encryptedSnapshot()
        try Data("unlisted".utf8).write(to: files.appendingPathComponent("extra.txt"))
        XCTAssertThrowsError(try store.importBitwarden(data: data, attachmentsDirectory: root))
        XCTAssertEqual(try store.encryptedSnapshot(), snapshot)
    }

    func testBitwardenModernCipherDirectorySuffixesAndSanitizationCollisionsFailClosed() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let kept = VaultEntry(name: "existing")
        let existing = VaultPayload(entries: [kept])
        let cases: [(names: [String], directories: [String])] = [
            // Official duplicate-name output; JSON does not say which ciphers
            // had attachments, so array order alone is not a reliable mapping.
            (["Example", "Example"], ["Example", "Example_1"]),
            (["Example", "Example", "Example"], ["Example", "Example_1", "Example_2"]),
            // Missing unsuffixed directory must not let a generated _1 directory
            // be mistaken for an unrelated cipher whose literal name ends in _1.
            (["Example", "Example", "Example_1"], ["Example_1"]),
            // The exporter keys its cipher counter by ORIGINAL name. These
            // different names therefore collide at one sanitized directory.
            (["Example:Name", "Example?Name"], ["Example_Name"])
        ]
        for (caseIndex, testCase) in cases.enumerated() {
            let root = directory.appendingPathComponent("case-\(caseIndex)")
            let items: [[String: Any]] = testCase.names.enumerated().map {
                ["id": "cipher-\($0.offset)", "name": $0.element, "type": 1, "login": [:] as [String: Any]]
            }
            let data = try JSONSerialization.data(withJSONObject: ["encrypted": false, "items": items])
            for name in testCase.directories {
                let files = root.appendingPathComponent("attachments").appendingPathComponent(name)
                try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
                try Data(name.utf8).write(to: files.appendingPathComponent("file.txt"))
            }
            try data.write(to: root.appendingPathComponent("data.json"))
            XCTAssertThrowsError(try BitwardenImporter.importVault(data: data, into: existing,
                attachmentsDirectory: root)) { error in
                guard case BitwardenImporter.AttachmentImportError.ambiguousDirectory = error else {
                    return XCTFail("\(error)")
                }
            }
            XCTAssertEqual(existing.entries, [kept])
        }
    }

    func testBitwardenUnrelatedDuplicateNamesDoNotBlockUniqueAttachmentDirectories() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let cases: [(names: [String], folder: String, owner: Int)] = [
            (["Duplicate", "Duplicate", "Unique"], "Unique", 2),
            (["Other:Name", "Other?Name", "Unique"], "Unique", 2),
            (["Duplicate", "Duplicate", "Example", "Example_1"], "Example_1", 3),
            // Counters belong to original names, not their sanitized spelling.
            (["Example:Name", "Example?Name", "Example_Name_1"], "Example_Name_1", 2),
            (["Duplicate", "Duplicate", "Example_01"], "Example_01", 2)
        ]
        for (caseIndex, testCase) in cases.enumerated() {
            let root = directory.appendingPathComponent("case-\(caseIndex)")
            let files = root.appendingPathComponent("attachments").appendingPathComponent(testCase.folder)
            try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
            let items: [[String: Any]] = testCase.names.enumerated().map {
                ["id": "cipher-\($0.offset)", "name": $0.element, "type": 1, "login": [:] as [String: Any]]
            }
            let data = try JSONSerialization.data(withJSONObject: ["items": items])
            try data.write(to: root.appendingPathComponent("data.json"))
            let bytes = Data("attachment-\(caseIndex)".utf8)
            try bytes.write(to: files.appendingPathComponent("file.txt"))
            let imported = try BitwardenImporter.importVault(data: data, into: VaultPayload(), attachmentsDirectory: root)
            XCTAssertEqual(imported.importedCount, items.count)
            XCTAssertEqual(imported.attachmentSources.count, 1)
            let source = try XCTUnwrap(imported.attachmentSources.first)
            let owner = try XCTUnwrap(imported.payload.entries.first { $0.id == source.entryID })
            XCTAssertEqual(try rawObject(owner)["id"] as? String, "cipher-\(testCase.owner)")
            XCTAssertEqual(source.fileName, "file.txt")
            XCTAssertEqual(try Data(contentsOf: source.url), bytes)
        }
    }

    func testBitwardenIgnoresFinderMetadataAtRootButPreservesHiddenAttachments() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let attachments = directory.appendingPathComponent("attachments")
        let id = "5d157198-8414-4bda-a591-f8df9d8029db"
        let files = attachments.appendingPathComponent(id, isDirectory: true)
        try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
        let names = ["secret.txt", ".hidden-file", ".DS_Store"]
        let item: [String: Any] = ["id": id, "name": "Example", "type": 1,
            "login": [:] as [String: Any], "attachments": names.map { ["fileName": $0] }]
        let data = try JSONSerialization.data(withJSONObject: ["items": [item]])
        try data.write(to: directory.appendingPathComponent("data.json"))
        try Data("Finder metadata, not an attachment".utf8).write(to: attachments.appendingPathComponent(".DS_Store"))
        for name in names {
            try Data(("actual attachment " + name).utf8).write(to: files.appendingPathComponent(name))
        }
        let result = try BitwardenImporter.importVault(data: data, into: VaultPayload(), attachmentsDirectory: directory)
        XCTAssertEqual(result.importedCount, 1)
        XCTAssertEqual(result.attachmentSources.map(\.fileName).sorted(), names.sorted())
        let entry = try XCTUnwrap(result.payload.entries.first)
        for source in result.attachmentSources {
            XCTAssertEqual(source.entryID, entry.id)
            XCTAssertEqual(source.url.deletingLastPathComponent(), files)
            XCTAssertEqual(try Data(contentsOf: source.url), Data(("actual attachment " + source.fileName).utf8))
        }
    }

    func testBitwardenFinderMetadataExceptionDoesNotHideUnsafeOrUnknownRootEntries() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let attachments = directory.appendingPathComponent("attachments")
        try FileManager.default.createDirectory(at: attachments, withIntermediateDirectories: true)
        let data = Data(#"{"items":[{"id":"cipher","name":"Example","type":1,"login":{}}]}"#.utf8)
        try data.write(to: directory.appendingPathComponent("data.json"))
        let metadata = attachments.appendingPathComponent(".DS_Store")
        let target = directory.appendingPathComponent("external-file")
        try Data("must not follow".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: metadata, withDestinationURL: target)
        XCTAssertThrowsError(try BitwardenImporter.importVault(data: data, into: VaultPayload(), attachmentsDirectory: directory)) { error in
            guard case VaultError.unsafeAttachmentPath = error else { return XCTFail("\(error)") }
        }
        try FileManager.default.removeItem(at: metadata)
        try FileManager.default.createDirectory(at: metadata, withIntermediateDirectories: false)
        XCTAssertThrowsError(try BitwardenImporter.importVault(data: data, into: VaultPayload(), attachmentsDirectory: directory)) { error in
            XCTAssertEqual(error as? BitwardenImporter.AttachmentImportError, .unmappedDirectory)
        }
        try FileManager.default.removeItem(at: metadata)
        let unknown = attachments.appendingPathComponent(".unknown-file")
        try Data("not Finder metadata".utf8).write(to: unknown)
        XCTAssertThrowsError(try BitwardenImporter.importVault(data: data, into: VaultPayload(), attachmentsDirectory: directory)) { error in
            XCTAssertEqual(error as? BitwardenImporter.AttachmentImportError, .unsupportedLayout)
        }
    }

    func testBitwardenAttachmentImportReportsSpecificReasonsWithoutImportedValues() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let root = directory.appendingPathComponent("export")
        let attachments = root.appendingPathComponent("attachments")
        let files = attachments.appendingPathComponent("Private item")
        try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
        let data = Data(#"{"items":[{"id":"private-id","name":"Private item","type":1,"login":{},"attachments":[{"fileName":"private-file.txt"}]}]}"#.utf8)
        try data.write(to: root.appendingPathComponent("data.json"))
        func assertFailure(_ expected: BitwardenImporter.AttachmentImportError,
                           data input: Data, directory selected: URL?) {
            XCTAssertThrowsError(try BitwardenImporter.importVault(data: input, into: VaultPayload(),
                attachmentsDirectory: selected)) { error in
                guard let reason = error as? BitwardenImporter.AttachmentImportError else {
                    return XCTFail("\(error)")
                }
                XCTAssertEqual(reason, expected)
                XCTAssertFalse(reason.localizedDescription.contains("Private item"))
                XCTAssertFalse(reason.localizedDescription.contains("private-id"))
                XCTAssertFalse(reason.localizedDescription.contains("private-file.txt"))
            }
        }
        assertFailure(.directoryRequired, data: data, directory: nil)
        assertFailure(.filesMismatch, data: data, directory: root)
        let withoutMetadata = Data(#"{"items":[{"id":"private-id","name":"Private item","type":1,"login":{}}]}"#.utf8)
        assertFailure(.exportChanged, data: withoutMetadata, directory: root)
        try Data("file contents".utf8).write(to: files.appendingPathComponent("private-file.txt"))
        let unknown = attachments.appendingPathComponent("unknown")
        try FileManager.default.moveItem(at: files, to: unknown)
        assertFailure(.unmappedDirectory, data: data, directory: root)
        try FileManager.default.removeItem(at: unknown)
        try Data("unexpected root file".utf8).write(to: attachments.appendingPathComponent("file.txt"))
        assertFailure(.unsupportedLayout, data: data, directory: root)
        try FileManager.default.removeItem(at: attachments)
        assertFailure(.missingFiles, data: data, directory: root)
        let invalid = Data(#"{"items":[{"id":"private-id","name":"Private item","type":1,"login":{},"attachments":"invalid"}]}"#.utf8)
        assertFailure(.invalidMetadata, data: invalid, directory: nil)
    }

    func testBitwardenLegacyIDsPermitDuplicateNamesAndModernLiteralSuffixIsNotRewritten() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let legacyRoot = directory.appendingPathComponent("legacy")
        let legacyData = Data(#"{"items":[{"id":"first-id","name":"Duplicate","type":1,"login":{}},{"id":"second-id","name":"Duplicate","type":1,"login":{}}]}"#.utf8)
        for id in ["first-id", "second-id"] {
            let files = legacyRoot.appendingPathComponent("attachments").appendingPathComponent(id)
            try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
            try Data(id.utf8).write(to: files.appendingPathComponent("original.v1.txt"))
        }
        try legacyData.write(to: legacyRoot.appendingPathComponent("data.json"))
        let legacy = try BitwardenImporter.importVault(data: legacyData, into: VaultPayload(),
            attachmentsDirectory: legacyRoot)
        XCTAssertEqual(legacy.importedCount, 2)
        XCTAssertEqual(legacy.attachmentSources.count, 2)
        for source in legacy.attachmentSources {
            let entry = try XCTUnwrap(legacy.payload.entries.first { $0.id == source.entryID })
            let sourceID = try XCTUnwrap(try rawObject(entry)["id"] as? String)
            XCTAssertEqual(source.url.deletingLastPathComponent().lastPathComponent, sourceID)
            XCTAssertEqual(source.fileName, "original.v1.txt", "Legacy filenames must not be modernized")
        }
        let modernRoot = directory.appendingPathComponent("modern")
        let files = modernRoot.appendingPathComponent("attachments/Example_1")
        try FileManager.default.createDirectory(at: files, withIntermediateDirectories: true)
        let modernData = Data(#"{"items":[{"id":"literal-id","name":"Example_1","type":1,"login":{}}]}"#.utf8)
        try modernData.write(to: modernRoot.appendingPathComponent("data.json"))
        try Data("actual bytes".utf8).write(to: files.appendingPathComponent("file_1.txt"))
        let modern = try BitwardenImporter.importVault(data: modernData, into: VaultPayload(),
            attachmentsDirectory: modernRoot)
        XCTAssertEqual(modern.importedCount, 1)
        XCTAssertEqual(modern.attachmentSources.first?.fileName, "file_1.txt")
        XCTAssertEqual(modern.attachmentSources.first?.url, files.appendingPathComponent("file_1.txt"))
    }

    @MainActor
    func testBitwardenMissingAmbiguousUnsafeAndPartialImportsAreAtomic() async throws {
        let manager = FileManager.default
        let directory = try makeTemporaryDirectory()
        defer { try? manager.removeItem(at: directory) }
        let store = VaultStore(vaultURL: directory.appendingPathComponent("vault.unipass"), preferences: preferences)
        try await store.create(password: "bitwarden-atomic-password")
        defer { store.lock() }
        let kept = VaultEntry(name: "keep", modifiedAt: Date(timeIntervalSince1970: 0))
        try store.save(kept)
        // save() updates modifiedAt; rollback must preserve the committed entry,
        // not the pre-save draft (whose timestamp may only differ subsecond).
        let entriesBeforeImport = store.payload.entries
        let snapshot = try store.encryptedSnapshot()
        let missing = Data(#"{"items":[{"id":"cipher","name":"Example","type":1,"login":{},"attachments":[{"fileName":"missing.txt"}]}]}"#.utf8)
        XCTAssertThrowsError(try store.importBitwarden(data: missing))
        let root = directory.appendingPathComponent("export")
        let files = root.appendingPathComponent("attachments/Example")
        try manager.createDirectory(at: files, withIntermediateDirectories: true)
        try missing.write(to: root.appendingPathComponent("data.json"))
        XCTAssertThrowsError(try store.importBitwarden(data: missing, attachmentsDirectory: root))
        let ambiguous = Data(#"{"items":[{"id":"one","name":"Example","type":1,"login":{}},{"id":"two","name":"Example","type":1,"login":{}}]}"#.utf8)
        try ambiguous.write(to: root.appendingPathComponent("data.json"))
        try Data("content".utf8).write(to: files.appendingPathComponent("example.txt"))
        XCTAssertThrowsError(try store.importBitwarden(data: ambiguous, attachmentsDirectory: root))
        let unsafe = Data(#"{"items":[{"id":"../escape","name":"Example","type":1,"login":{}}]}"#.utf8)
        try unsafe.write(to: root.appendingPathComponent("data.json"))
        XCTAssertThrowsError(try store.importBitwarden(data: unsafe, attachmentsDirectory: root))
        let valid = Data(#"{"items":[{"id":"cipher","name":"Example","type":1,"login":{}}]}"#.utf8)
        try valid.write(to: root.appendingPathComponent("data.json"))
        let link = files.appendingPathComponent("link.txt")
        try manager.createSymbolicLink(at: link, withDestinationURL: files.appendingPathComponent("example.txt"))
        XCTAssertThrowsError(try store.importBitwarden(data: valid, attachmentsDirectory: root))
        try manager.removeItem(at: link)
        let unknown = root.appendingPathComponent("attachments/unmapped")
        try manager.createDirectory(at: unknown, withIntermediateDirectories: false)
        XCTAssertThrowsError(try store.importBitwarden(data: valid, attachmentsDirectory: root))
        try manager.removeItem(at: unknown)
        XCTAssertEqual(store.payload.entries, entriesBeforeImport)
        XCTAssertEqual(try store.encryptedSnapshot(), snapshot)
        // Both files inventory successfully. The first blob is written, then the
        // second collides with existing content; the first must be rolled back.
        try Data("first".utf8).write(to: files.appendingPathComponent("a.txt"))
        try store.importBitwarden(data: valid, attachmentsDirectory: root)
        let imported = try XCTUnwrap(store.payload.entries.first { $0.id != kept.id })
        let before = store.payload.entries
        let committed = try store.encryptedSnapshot()
        let documents = directory.appendingPathComponent("documents")
        let blobs = try manager.contentsOfDirectory(atPath: documents.path).sorted()
        try Data("new".utf8).write(to: files.appendingPathComponent("0-new.txt"))
        try Data("changed".utf8).write(to: files.appendingPathComponent("example.txt"))
        XCTAssertThrowsError(try store.importBitwarden(data: valid, attachmentsDirectory: root))
        XCTAssertEqual(store.payload.entries, before)
        XCTAssertEqual(try store.encryptedSnapshot(), committed)
        XCTAssertEqual(try manager.contentsOfDirectory(atPath: documents.path).sorted(), blobs)
        XCTAssertEqual(imported.attachments.count, 2)
        XCTAssertNotEqual(snapshot, committed)
    }

    @MainActor
    func testFirstLaunchCreateWithoutEditingConsentKeepsEntriesReadOnly() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        preferences.removeObject(forKey: "allowMobileEditing")
        let store = VaultStore(vaultURL: directory.appendingPathComponent("vault.unipass"), preferences: preferences)
        XCTAssertFalse(store.allowMobileEditing)
        XCTAssertFalse(store.hasVault)
        try await store.create(password: "first-launch-password")
        defer { store.lock() }
        XCTAssertTrue(store.hasVault)
        XCTAssertTrue(store.isUnlocked)
        XCTAssertTrue(store.payload.entries.isEmpty)
        XCTAssertFalse(store.allowMobileEditing)
        XCTAssertNil(preferences.object(forKey: "allowMobileEditing"))
        let snapshot = try store.encryptedSnapshot()
        #if !targetEnvironment(macCatalyst)
        XCTAssertFalse(store.canEdit)
        XCTAssertThrowsError(try store.save(VaultEntry(name: "blocked"))) { error in
            guard case VaultError.mobileEditingDisabled = error else { return XCTFail("\(error)") }
        }
        XCTAssertThrowsError(try store.addFolder(name: "blocked")) { error in
            guard case VaultError.mobileEditingDisabled = error else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(try store.encryptedSnapshot(), snapshot)
        #endif
        store.lock()
        try await store.unlock(password: "first-launch-password")
        XCTAssertFalse(store.allowMobileEditing)
        do {
            try await store.create(password: "must not overwrite")
            XCTFail("Bootstrap exemption must not allow overwriting an existing vault")
        } catch {
            guard case VaultError.vaultAlreadyExists = error else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), snapshot)
        store.allowMobileEditing = true
        try store.save(VaultEntry(name: "allowed after enabling editing"))
        XCTAssertEqual(store.payload.entries.count, 1)
    }

    @MainActor
    func testMobileReadOnlyPreferencesProtectMutationsButPermitReadsAndSync() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("vault.unipass")
        let store = VaultStore(vaultURL: url, preferences: preferences)
        try await store.create(password: "read-only-password")
        defer { store.lock() }
        try store.addFolder(name: "folder")
        let folder = try XCTUnwrap(store.payload.folders.first)
        let entry = VaultEntry(name: "read only", folderID: folder.id, originalJSON: "{}")
        try store.save(entry)
        let file = directory.appendingPathComponent("file.txt")
        try Data("readable".utf8).write(to: file)
        try store.addAttachment(entryID: entry.id, from: file)
        let attachment = try XCTUnwrap(store.payload.entries.first?.attachments.first)
        preferences.removeObject(forKey: "allowMobileEditing")
        let defaultStore = VaultStore(vaultURL: url, preferences: preferences)
        XCTAssertFalse(defaultStore.allowMobileEditing, "Absent preference defaults to read-only")
        store.allowMobileEditing = false
        XCTAssertFalse(preferences.bool(forKey: "allowMobileEditing"))
        #if targetEnvironment(macCatalyst)
        XCTAssertTrue(store.canEdit)
        XCTAssertNoThrow(try store.requireEditingAllowed())
        #else
        XCTAssertFalse(store.canEdit)
        let before = store.payload.entries
        let snapshot = try store.encryptedSnapshot()
        let mutations: [() throws -> Void] = [
            { try store.requireEditingAllowed() },
            { try store.save(entry) },
            { try store.addFolder(name: "blocked") },
            { try store.renameFolder(id: folder.id, name: "blocked") },
            { try store.deleteFolder(id: folder.id) },
            { try store.trash(id: entry.id) },
            { try store.restore(id: entry.id) },
            { try store.permanentlyDelete(id: entry.id) },
            { try store.removeOriginalJSON(id: entry.id) },
            { try store.addAttachment(entryID: entry.id, from: file) },
            { try store.removeAttachment(entryID: entry.id, attachmentID: attachment.id) },
            { _ = try store.importBitwarden(data: Data(Self.bitwardenJSON.utf8)) }
        ]
        for mutation in mutations {
            XCTAssertThrowsError(try mutation()) { error in
                guard case VaultError.mobileEditingDisabled = error else { return XCTFail("\(error)") }
            }
        }
        do {
            try await store.changePassword(current: "read-only-password", new: "blocked")
            XCTFail("Read-only password change must fail")
        } catch {
            guard case VaultError.mobileEditingDisabled = error else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(store.payload.entries, before)
        XCTAssertEqual(try store.encryptedSnapshot(), snapshot)
        #endif
        XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id), Data("readable".utf8))
        let snapshotForSync = try store.encryptedData()
        try store.replaceEncryptedVault(snapshotForSync)
        try await store.replaceEncryptedVaultAsync(snapshotForSync)
        XCTAssertEqual(store.payload.entries.first?.attachments, [attachment])
        XCTAssertEqual(try store.attachmentData(entryID: entry.id, attachmentID: attachment.id), Data("readable".utf8))
        store.allowMobileEditing = true
        XCTAssertTrue(preferences.bool(forKey: "allowMobileEditing"))
        XCTAssertTrue(VaultStore(vaultURL: url, preferences: preferences).allowMobileEditing)
        try store.removeOriginalJSON(id: entry.id)
        XCTAssertNil(store.payload.entries.first?.originalJSON)
    }

    @MainActor
    private func makeBackupFixture(at directory: URL, password: String = "complete-backup-password") async throws
        -> (store: VaultStore, entry: VaultEntry, attachment: VaultAttachment, bytes: Data) {
        let store = VaultStore(vaultURL: directory.appendingPathComponent("source/vault.unipass"), preferences: preferences)
        try await store.create(password: password)
        let entry = VaultEntry(name: "backup with attachment")
        try store.save(entry)
        let bytes = Data("private attachment bytes".utf8)
        let file = directory.appendingPathComponent("input.txt")
        try bytes.write(to: file)
        try store.addAttachment(entryID: entry.id, from: file)
        let attachment = try XCTUnwrap(store.payload.entries.first?.attachments.first)
        return (store, entry, attachment, bytes)
    }

    @MainActor
    func testCompleteBackupSurvivesRemovalOfOriginalVaultAndDocuments() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        try fixture.store.trash(id: fixture.entry.id)
        let vault = try fixture.store.encryptedSnapshot()
        let backup = try fixture.store.backupData()
        let contents = try VaultBackup.decode(backup)
        XCTAssertEqual(contents.vault, vault)
        XCTAssertEqual(Set(contents.attachments.keys), [fixture.attachment.id])
        XCTAssertNil(backup.range(of: fixture.bytes))
        XCTAssertNoThrow(try VaultBackup.validate(backup))
        fixture.store.lock()
        try FileManager.default.removeItem(at: fixture.store.vaultURL.deletingLastPathComponent())
        let target = VaultStore(vaultURL: directory.appendingPathComponent("new/nested/vault.unipass"), preferences: preferences)
        try await target.restoreBackup(data: backup, password: "complete-backup-password")
        defer { target.lock() }
        XCTAssertEqual(try target.encryptedSnapshot(), vault)
        XCTAssertEqual(try Data(contentsOf: target.vaultURL), vault)
        XCTAssertNotNil(target.payload.entries.first?.deletedAt)
        try target.restore(id: fixture.entry.id)
        XCTAssertEqual(try target.attachmentData(entryID: fixture.entry.id, attachmentID: fixture.attachment.id), fixture.bytes)
    }

    @MainActor
    func testCurrentRestorePreservesPortableOldVersionAndRestoresDeletedAttachment() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        let store = fixture.store
        defer { store.lock() }
        let original = try store.backupData()
        try store.save(VaultEntry(name: "newer content"))
        let before = try store.encryptedSnapshot()
        try await store.restoreBackupIntoCurrent(original)
        XCTAssertEqual(store.payload.entries.count, 1)
        let backups = try FileManager.default.contentsOfDirectory(at: store.backupDirectory, includingPropertiesForKeys: nil)
        let preserved = try XCTUnwrap(try backups.map { try Data(contentsOf: $0) }.first {
            try VaultBackup.decode($0).vault == before
        })
        try store.removeAttachment(entryID: fixture.entry.id, attachmentID: fixture.attachment.id)
        XCTAssertThrowsError(try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL))
        try await store.restoreBackupIntoCurrent(preserved)
        XCTAssertEqual(try store.encryptedSnapshot(), before)
        XCTAssertEqual(try store.attachmentData(entryID: fixture.entry.id, attachmentID: fixture.attachment.id), fixture.bytes)
        let empty = VaultStore(vaultURL: directory.appendingPathComponent("empty/vault.unipass"), preferences: preferences)
        try await empty.create(password: "complete-backup-password")
        defer { empty.lock() }
        XCTAssertEqual(try empty.backupData(), try empty.encryptedSnapshot(), "No-attachment exports retain legacy bytes")
        try await store.restoreBackupIntoCurrent(empty.backupData())
        XCTAssertTrue(store.payload.entries.isEmpty)
    }

    @MainActor
    func testBackupTamperingAndWrongPasswordNeverChangeCurrentVaultOrBlobs() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        let store = fixture.store
        defer { store.lock() }
        let backup = try store.backupData()
        let original = try VaultBackup.decode(backup)
        let vault = try store.encryptedSnapshot()
        let blob = try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL)
        var missing = original
        missing.attachments = [:]
        var extra = original
        extra.attachments[UUID()] = blob
        var damaged = original
        var corruptBlob = blob
        corruptBlob[corruptBlob.startIndex] ^= 1
        damaged.attachments[fixture.attachment.id] = corruptBlob
        let foreign = try VaultCrypto.prepare(VaultPayload(), password: VaultCrypto.passwordData("other-password")).data
        let invalid = [try VaultBackup.encode(missing, preservingContainer: true),
                       try VaultBackup.encode(extra), try VaultBackup.encode(damaged),
                       Data(backup.dropLast()), backup + Data([0]), foreign]
        for data in invalid {
            do {
                try await store.restoreBackupIntoCurrent(data)
                XCTFail("Invalid backup must fail")
            } catch { }
            XCTAssertEqual(try Data(contentsOf: store.vaultURL), vault)
            XCTAssertEqual(try store.encryptedSnapshot(), vault)
            XCTAssertEqual(try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL), blob)
            let target = VaultStore(vaultURL: directory.appendingPathComponent("rejected/vault.unipass"), preferences: preferences)
            do {
                try await target.restoreBackup(data: data, password: "complete-backup-password")
                XCTFail("Invalid initial restore must fail")
            } catch { }
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.vaultURL.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: target.vaultURL.deletingLastPathComponent().appendingPathComponent("documents").path))
        }
        let target = VaultStore(vaultURL: directory.appendingPathComponent("wrong/vault.unipass"), preferences: preferences)
        do {
            try await target.restoreBackup(data: backup, password: "wrong")
            XCTFail("Wrong password must fail")
        } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.vaultURL.path))
    }

    func testBackupBinaryBoundsDuplicateIDsAndExclusiveWriter() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let vault = try VaultCrypto.prepare(VaultPayload(), password: Data("bounds-password".utf8)).data
        let id = UUID()
        let blob = Data(repeating: 7, count: 28)
        let data = try VaultBackup.encode(.init(vault: vault, attachments: [id: blob]))
        let recordOffset = VaultBackup.magic.count + 12 + vault.count
        let record = data.subdata(in: recordOffset..<data.count)
        var duplicate = data
        duplicate[VaultBackup.magic.count + 11] = 2
        duplicate.append(record)
        XCTAssertThrowsError(try VaultBackup.validate(duplicate))
        var unsafe = data
        unsafe.replaceSubrange(recordOffset..<(recordOffset + 36), with: Data(repeating: 47, count: 36))
        XCTAssertThrowsError(try VaultBackup.validate(unsafe))
        var excessiveCount = data
        excessiveCount.replaceSubrange((VaultBackup.magic.count + 8)..<(VaultBackup.magic.count + 12), with: [0, 0, 4, 1])
        XCTAssertThrowsError(try VaultBackup.validate(excessiveCount))
        var excessiveLength = data
        excessiveLength.replaceSubrange((recordOffset + 36)..<(recordOffset + 44), with: Data(repeating: 255, count: 8))
        XCTAssertThrowsError(try VaultBackup.validate(excessiveLength))
        for length in [0, VaultBackup.magic.count, recordOffset - 1, data.count - 1] {
            XCTAssertThrowsError(try VaultBackup.validate(Data(data.prefix(length))))
        }
        XCTAssertNoThrow(try VaultBackup.checkLimits(bytes: VaultBackup.maximumBytes, count: VaultCrypto.maximumAttachmentCount))
        XCTAssertThrowsError(try VaultBackup.checkLimits(bytes: VaultBackup.maximumBytes + 1, count: 0))
        XCTAssertThrowsError(try VaultBackup.checkLimits(bytes: 0, count: VaultCrypto.maximumAttachmentCount + 1))
        let sharedBlob = Data(count: VaultCrypto.maximumAttachmentBytes + 28)
        let tooManyBytes = Dictionary(uniqueKeysWithValues: (0..<17).map { _ in (UUID(), sharedBlob) })
        XCTAssertThrowsError(try VaultBackup.encode(.init(vault: vault, attachments: tooManyBytes)))
        var prefixed = Data([42])
        prefixed.append(data)
        XCTAssertNoThrow(try VaultBackup.validate(prefixed.dropFirst()), "Nonzero Data indices must be safe")
        let target = directory.appendingPathComponent("nested/backup.enc")
        try VaultBackup.write(data, to: target)
        XCTAssertThrowsError(try VaultBackup.write(vault, to: target))
        XCTAssertEqual(try Data(contentsOf: target), data)
        XCTAssertThrowsError(try VaultBackup.write(Data("invalid".utf8), to: target))
        XCTAssertEqual(try Data(contentsOf: target), data)
        let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: target.deletingLastPathComponent().path), ["backup.enc"])
    }

    func testBackupWriterAcceptsContainerLargerThanVaultEnvelopeLimit() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let prepared = try VaultCrypto.prepare(VaultPayload(), password: Data("large-backup-password".utf8))
        let plaintext = Data(count: VaultCrypto.maximumEnvelopeBytes / 2 + 1)
        let attachments = try ["first.bin", "second.bin"].map {
            VaultAttachment(fileName: $0, byteCount: Int64(plaintext.count), key: try VaultCrypto.randomBytes(count: 32))
        }
        let entry = VaultEntry(attachments: attachments)
        let payload = VaultPayload(entries: [entry])
        let vault = try VaultCrypto.seal(payload, key: prepared.key, header: prepared.header)
        let blobs = try Dictionary(uniqueKeysWithValues: attachments.map {
            ($0.id, try VaultCrypto.sealAttachment(plaintext, entryID: entry.id, attachment: $0))
        })
        let backup = try VaultBackup.encode(.init(vault: vault, attachments: blobs))
        XCTAssertGreaterThan(backup.count, VaultCrypto.maximumEnvelopeBytes)
        let vaultURL = directory.appendingPathComponent("vault.unipass")
        let folder = BackupFiles.directory(vaultURL: vaultURL)
        let url = folder.appendingPathComponent("complete-large.enc")
        let legacyURL = folder.appendingPathComponent("legacy.enc")
        try VaultBackup.write(backup, to: url)
        try VaultDisk.write(prepared.data, to: legacyURL, creating: true, expected: nil)
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber,
                       NSNumber(value: backup.count))
        XCTAssertNoThrow(try VaultBackup.validate(backup))
        XCTAssertNoThrow(try VaultBackup.authenticate(VaultBackup.decode(backup), payload: payload))
        XCTAssertThrowsError(try VaultDisk.read(url), "Full backups intentionally exceed the pure-vault disk limit")
        XCTAssertThrowsError(try BackupFiles.read(url, maximumBytes: VaultCrypto.maximumEnvelopeBytes))
        XCTAssertThrowsError(try BackupFiles.readScoped(url, maximumBytes: VaultCrypto.maximumEnvelopeBytes))

        let records = try BackupFiles.records(vaultURL: vaultURL)
        XCTAssertEqual(Set(records.map { $0.url.resolvingSymlinksInPath() }),
                       [url.resolvingSymlinksInPath(), legacyURL.resolvingSymlinksInPath()])
        let explicitRecords = try BackupFiles.records(vaultURL: vaultURL, directory: folder)
        XCTAssertEqual(Set(explicitRecords.map(\.url)), Set(records.map(\.url)))
        for record in records {
            let expected = record.url.resolvingSymlinksInPath() == url.resolvingSymlinksInPath() ? backup : prepared.data
            XCTAssertEqual(record.size, Int64(expected.count))
            XCTAssertEqual(try BackupFiles.read(record.url, maximumBytes: VaultBackup.maximumBytes), expected)
            XCTAssertEqual(try BackupFiles.readScoped(record.url, maximumBytes: VaultBackup.maximumBytes), expected)
        }
    }

    @MainActor
    func testReadOnlyBackupExportAndRestoreCancellation() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        let store = fixture.store
        defer { store.lock() }
        let backup = try store.backupData()
        let snapshot = try store.encryptedSnapshot()
        store.allowMobileEditing = false
        XCTAssertEqual(try VaultBackup.decode(store.backupData()).vault, snapshot)
        #if !targetEnvironment(macCatalyst)
        do {
            try await store.restoreBackupIntoCurrent(backup)
            XCTFail("Read-only restore must fail")
        } catch {
            guard case VaultError.mobileEditingDisabled = error else { return XCTFail("\(error)") }
        }
        #endif
        store.allowMobileEditing = true
        var started = false
        let task = Task { @MainActor in
            started = true
            try await store.restoreBackupIntoCurrent(backup)
        }
        // Wait until restore has entered its detached PBKDF2 suspension.
        while !started { await Task.yield() }
        store.lock()
        do { try await task.value; XCTFail("Locked restore must not commit") } catch { }
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), snapshot)
        try await store.unlock(password: "complete-backup-password")
        #if !targetEnvironment(macCatalyst)
        started = false
        let permissionTask = Task { @MainActor in
            started = true
            try await store.restoreBackupIntoCurrent(backup)
        }
        while !started { await Task.yield() }
        store.allowMobileEditing = false
        store.allowMobileEditing = true
        do { try await permissionTask.value; XCTFail("Permission revocation must cancel late commit") } catch { }
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), snapshot)
        #endif
    }

    @MainActor
    func testBackupRequiresCompleteAttachmentsAndExternalSnapshotBackupIsPortable() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        let store = fixture.store
        defer { store.lock() }
        let snapshot = try store.encryptedSnapshot()
        let blob = try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL)
        try VaultAttachmentDisk.removeBlob(fixture.attachment.id, vault: store.vaultURL)
        XCTAssertThrowsError(try store.backupData())
        XCTAssertThrowsError(try store.preserveBackup())
        do {
            try await store.restoreBackupIntoCurrent(snapshot)
            XCTFail("Incomplete current library must not be replaced")
        } catch { }
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), snapshot)
        var damaged = blob
        damaged[damaged.startIndex] ^= 1
        try VaultAttachmentDisk.writeBlob(damaged, id: fixture.attachment.id, vault: store.vaultURL)
        XCTAssertThrowsError(try store.backupData(), "Export authenticates every attachment, not only its size")
        XCTAssertThrowsError(try store.preserveBackup())
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), snapshot)
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL), damaged)
        try VaultAttachmentDisk.removeBlob(fixture.attachment.id, vault: store.vaultURL)
        try VaultAttachmentDisk.writeBlob(blob, id: fixture.attachment.id, vault: store.vaultURL)
        let remote = try VaultCrypto.prepare(store.payload, password: VaultCrypto.passwordData("complete-backup-password"))
        XCTAssertNotEqual(remote.data, snapshot)
        XCTAssertEqual(try VaultBackup.decode(store.backupData(for: remote.data)).vault, remote.data)
        try remote.data.write(to: store.vaultURL, options: .atomic)
        await store.checkForExternalChanges()
        XCTAssertNotNil(store.externalChangeMessage)
        let backups = try FileManager.default.contentsOfDirectory(at: store.backupDirectory, includingPropertiesForKeys: nil)
        let backup = try XCTUnwrap(try backups.map { try Data(contentsOf: $0) }.first {
            try VaultBackup.decode($0).vault == snapshot
        })
        try VaultAttachmentDisk.removeBlob(fixture.attachment.id, vault: store.vaultURL)
        let target = VaultStore(vaultURL: directory.appendingPathComponent("external-recovery/vault.unipass"), preferences: preferences)
        try await target.restoreBackup(data: backup, password: "complete-backup-password")
        defer { target.lock() }
        XCTAssertEqual(try target.attachmentData(entryID: fixture.entry.id, attachmentID: fixture.attachment.id), fixture.bytes)
    }

    @MainActor
    func testCurrentRestoreRemapsConflictingCiphertextWithoutOverwritingExistingBlob() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        let store = fixture.store
        defer { store.lock() }
        let before = try store.encryptedSnapshot()
        let originalBlob = try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL)
        var incomingPayload = store.payload
        incomingPayload.entries[0].attachments[0].key = try VaultCrypto.randomBytes(count: 32)
        let incomingAttachment = incomingPayload.entries[0].attachments[0]
        let incomingBlob = try VaultCrypto.sealAttachment(fixture.bytes, entryID: fixture.entry.id, attachment: incomingAttachment)
        let incomingVault = try VaultCrypto.prepare(incomingPayload, password: VaultCrypto.passwordData("complete-backup-password"))
        let backup = try VaultBackup.encode(.init(vault: incomingVault.data, attachments: [incomingAttachment.id: incomingBlob]))
        try await store.restoreBackupIntoCurrent(backup)
        let remapped = try XCTUnwrap(store.payload.entries.first?.attachments.first)
        XCTAssertNotEqual(remapped.id, fixture.attachment.id)
        XCTAssertEqual(try store.attachmentData(entryID: fixture.entry.id, attachmentID: remapped.id), fixture.bytes)
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL), originalBlob)
        let backups = try FileManager.default.contentsOfDirectory(at: store.backupDirectory, includingPropertiesForKeys: nil)
        XCTAssertTrue(try backups.contains { try VaultBackup.decode(Data(contentsOf: $0)).vault == before })
        // A corrupt unreferenced sibling is never overwritten either; remapping
        // lets a portable backup restore usable content without touching it.
        try store.removeAttachment(entryID: fixture.entry.id, attachmentID: remapped.id)
        try VaultAttachmentDisk.removeBlob(fixture.attachment.id, vault: store.vaultURL)
        let corrupt = Data("corrupt existing ciphertext".utf8)
        try VaultAttachmentDisk.writeBlob(corrupt, id: fixture.attachment.id, vault: store.vaultURL)
        try await store.restoreBackupIntoCurrent(backup)
        let recovered = try XCTUnwrap(store.payload.entries.first?.attachments.first)
        XCTAssertNotEqual(recovered.id, fixture.attachment.id)
        XCTAssertEqual(try store.attachmentData(entryID: fixture.entry.id, attachmentID: recovered.id), fixture.bytes)
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: store.vaultURL), corrupt)
    }

    @MainActor
    func testInitialRestoreCollisionRollsBackWithoutChangingExistingFiles() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        defer { fixture.store.lock() }
        let backup = try fixture.store.backupData()
        let url = directory.appendingPathComponent("collision/vault.unipass")
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let corrupt = Data("do not overwrite".utf8)
        try VaultAttachmentDisk.writeBlob(corrupt, id: fixture.attachment.id, vault: url)
        let target = VaultStore(vaultURL: url, preferences: preferences)
        do {
            try await target.restoreBackup(data: backup, password: "complete-backup-password")
            XCTFail("Initial restore must preserve exact vault bytes and reject UUID conflicts")
        } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(fixture.attachment.id, vault: url), corrupt)
        // Reusing identical existing ciphertext needs no overwrite or re-seal.
        try VaultAttachmentDisk.removeBlob(fixture.attachment.id, vault: url)
        let contents = try VaultBackup.decode(backup)
        try VaultAttachmentDisk.writeBlob(try XCTUnwrap(contents.attachments[fixture.attachment.id]), id: fixture.attachment.id, vault: url)
        try await target.restoreBackup(data: backup, password: "complete-backup-password")
        defer { target.lock() }
        XCTAssertEqual(try Data(contentsOf: url), contents.vault)
    }

    @MainActor
    func testExternalChangeWithMissingAttachmentDoesNotPublishPartialBackup() async throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = try await makeBackupFixture(at: directory)
        let store = fixture.store
        defer { store.lock() }
        try VaultAttachmentDisk.removeBlob(fixture.attachment.id, vault: store.vaultURL)
        try Data("external change".utf8).write(to: store.vaultURL, options: .atomic)
        XCTAssertThrowsError(try store.backupData())
        XCTAssertTrue(store.externalChangeMessage?.contains("complete local backup failed") == true)
        let files = try FileManager.default.contentsOfDirectory(atPath: store.backupDirectory.path)
        XCTAssertTrue(files.isEmpty)
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), Data("external change".utf8))
    }

    private func makeTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("UniPassTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func rawObject(_ entry: VaultEntry) throws -> [String: Any] {
        let raw = try XCTUnwrap(entry.originalJSON)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
    }

    private static let bitwardenJSON = #"""
    {
      "encrypted": false,
      "folders": [{"id":"source-folder", "name":"Personal"}],
      "items": [
        {
          "id":"source-login", "type":1, "name":"Login", "folderId":"source-folder",
          "favorite":true, "notes":"Notes", "creationDate":"2020-01-01T00:00:00Z",
          "login":{"username":"alice","password":"secret","totp":"MY======",
                   "uris":[{"uri":"https://example.com"},{"uri":"https://example.org"}]},
          "fields":[{"name":"text","value":"text","type":0},
                    {"name":"hidden","value":"hidden","type":1},
                    {"name":"boolean","value":true,"type":2},
                    {"name":"linked","value":null,"type":3,"linkedId":100}],
          "unknownFutureField":{"nested":[1,true,"Retained"]},
          "attachments":[]
        },
        {
          "id":"source-card", "type":3, "name":"Card", "folderId":"source-folder",
          "card":{"cardholderName":"Alice","brand":"Visa","number":"4111111111111111",
                  "expMonth":"12","expYear":"2030","code":"123"}
        }
      ]
    }
    """#
}

private actor MemoryWebDAV: WebDAVServing {
    private var data: Data?
    private var revision = 0
    private var uploads = 0
    private var objects: [UUID: Data] = [:]
    private var nextDownloadAction: (@MainActor () -> Void)?
    private var etag: String { "\"revision-\(revision)\"" }

    func testConnection() async throws { }
    func download() async throws -> WebDAVDownload? {
        let action = nextDownloadAction
        nextDownloadAction = nil
        if let action { await action() }
        return data.map { WebDAVDownload(data: $0, etag: etag) }
    }
    func upload(_ bytes: Data, expectedETag: String?, createOnly: Bool) async throws -> String? {
        if createOnly {
            guard data == nil, expectedETag == nil else { throw WebDAVError.preconditionFailed }
        } else {
            guard data != nil, expectedETag == etag else { throw WebDAVError.preconditionFailed }
        }
        data = bytes; revision += 1; uploads += 1
        return etag
    }
    func downloadAttachment(id: UUID) async throws -> WebDAVDownload? {
        objects[id].map { WebDAVDownload(data: $0, etag: "\"attachment\"") }
    }
    func uploadAttachment(_ data: Data, id: UUID) async throws -> String? {
        guard objects[id] == nil else { throw WebDAVError.preconditionFailed }
        objects[id] = data
        return "\"attachment\""
    }
    func bytes() -> Data? { data }
    func uploadCount() -> Int { uploads }
    func removeRemote() { data = nil; revision += 1 }
    func interceptNextDownload(_ action: @escaping @MainActor () -> Void) { nextDownloadAction = action }
}

import Foundation
import CryptoKit
import CommonCrypto
import Security
import Darwin

/// v1 is UTF-8 JSON with base64 Data values. All header fields are authenticated
/// using the binary AAD encoding below, not JSON key order or whitespace.
enum VaultCrypto {
    static let iterations = 600_000
    static let maximumIterations = 2_000_000
    static let maximumPlaintextBytes = 32 * 1024 * 1024
    static let maximumEnvelopeBytes = 48 * 1024 * 1024
    static let maximumAttachmentBytes = 32 * 1024 * 1024
    static let maximumAttachmentImportBytes: Int64 = 256 * 1024 * 1024
    static let maximumAttachmentCount = 1_024

    static func validAttachmentFileName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && name.utf8.count <= 255
            && !name.contains("/") && !name.contains("\\")
            && !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    }

    private static func attachmentAAD(entryID: UUID, attachment: VaultAttachment) -> Data {
        Data("uniPass.attachment.v1\u{0}\(entryID.uuidString)\u{0}\(attachment.id.uuidString)\u{0}\(attachment.byteCount)".utf8)
    }

    static func sealAttachment(_ data: Data, entryID: UUID, attachment: VaultAttachment) throws -> Data {
        guard data.count <= maximumAttachmentBytes else { throw VaultError.dataTooLarge }
        guard attachment.key.count == 32, Int64(data.count) == attachment.byteCount else {
            throw VaultError.invalidAttachment
        }
        return try AES.GCM.seal(data, using: SymmetricKey(data: attachment.key),
            authenticating: attachmentAAD(entryID: entryID, attachment: attachment)).combined!
    }

    static func openAttachment(_ data: Data, entryID: UUID, attachment: VaultAttachment) throws -> Data {
        guard data.count <= maximumAttachmentBytes + 28 else { throw VaultError.dataTooLarge }
        guard attachment.key.count == 32, attachment.byteCount >= 0,
              attachment.byteCount <= maximumAttachmentBytes,
              Int64(data.count) == attachment.byteCount + 28 else {
            throw VaultError.invalidAttachment
        }
        do {
            return try AES.GCM.open(AES.GCM.SealedBox(combined: data),
                using: SymmetricKey(data: attachment.key),
                authenticating: attachmentAAD(entryID: entryID, attachment: attachment))
        } catch { throw VaultError.invalidAttachment }
    }

    struct Header: Codable, Equatable {
        let version: Int
        let kdf: String
        let iterations: Int
        let salt: Data
        let cipher: String
    }

    struct Envelope: Codable {
        let header: Header
        let nonce: Data
        let ciphertext: Data
        let tag: Data
    }

    struct Opened {
        let payload: VaultPayload
        let key: SymmetricKey
        let header: Header
    }

    struct Prepared {
        let data: Data
        let key: SymmetricKey
        let header: Header
    }

    static func passwordData(_ password: String) throws -> Data {
        let data = Data(password.utf8)
        guard !data.isEmpty else { throw VaultError.emptyPassword }
        guard data.count <= 4096 else { throw VaultError.passwordTooLong }
        return data
    }

    static func randomBytes(count: Int) throws -> Data {
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard result == errSecSuccess else { throw VaultError.randomnessFailed }
        return data
    }

    static func newHeader() throws -> Header {
        Header(version: 1, kdf: "PBKDF2-HMAC-SHA256", iterations: iterations,
               salt: try randomBytes(count: 32), cipher: "AES-256-GCM")
    }

    static func validate(_ header: Header) throws {
        guard header.version == 1, header.kdf == "PBKDF2-HMAC-SHA256",
              header.cipher == "AES-256-GCM" else { throw VaultError.unsupportedFormat }
        // Validate BEFORE PBKDF2: never accept attacker-controlled unbounded work.
        guard (iterations...maximumIterations).contains(header.iterations),
              header.salt.count == 32 else { throw VaultError.invalidEnvelope }
    }

    static func decodeEnvelope(_ data: Data) throws -> Envelope {
        guard data.count <= maximumEnvelopeBytes else { throw VaultError.dataTooLarge }
        let envelope: Envelope
        do { envelope = try JSONDecoder().decode(Envelope.self, from: data) }
        catch { throw VaultError.invalidEnvelope }
        try validate(envelope.header)
        guard envelope.nonce.count == 12, envelope.tag.count == 16,
              envelope.ciphertext.count <= maximumPlaintextBytes else {
            throw VaultError.invalidEnvelope
        }
        return envelope
    }

    static func deriveKey(password: Data, header: Header) throws -> SymmetricKey {
        try validate(header)
        guard !password.isEmpty else { throw VaultError.emptyPassword }
        guard password.count <= 4096 else { throw VaultError.passwordTooLong }
        var derived = Data(count: 32)
        defer { derived.resetBytes(in: 0..<derived.count) }
        let status = derived.withUnsafeMutableBytes { output in
            password.withUnsafeBytes { passwordBytes in
                header.salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress!.assumingMemoryBound(to: Int8.self), password.count,
                        saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), header.salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(header.iterations),
                        output.baseAddress!.assumingMemoryBound(to: UInt8.self), 32)
                }
            }
        }
        guard status == kCCSuccess else { throw VaultError.derivationFailed }
        return SymmetricKey(data: derived)
    }

    private static func associatedData(_ header: Header) -> Data {
        // Fixed domain and algorithm names; integers are unsigned 32-bit big endian.
        var data = Data("uniPass.vault\u{0}".utf8)
        for value in [UInt32(header.version), UInt32(header.iterations)] {
            var value = value.bigEndian
            withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
        }
        data.append(Data(header.kdf.utf8))
        data.append(0)
        data.append(Data(header.cipher.utf8))
        data.append(0)
        data.append(header.salt)
        return data
    }

    static func validatePayload(_ payload: VaultPayload) throws {
        let folderIDs = Set(payload.folders.map(\.id))
        guard folderIDs.count == payload.folders.count,
              Set(payload.entries.map(\.id)).count == payload.entries.count else {
            throw VaultError.invalidPayload
        }
        var attachmentIDs = Set<UUID>()
        for entry in payload.entries {
            guard entry.folderID.map({ folderIDs.contains($0) }) ?? true,
                  Set(entry.fields.map(\.id)).count == entry.fields.count,
                  entry.fields.allSatisfy({ (0...3).contains($0.type) }) else {
                throw VaultError.invalidPayload
            }
            for attachment in entry.attachments {
                guard attachmentIDs.insert(attachment.id).inserted,
                      attachmentIDs.count <= maximumAttachmentCount,
                      validAttachmentFileName(attachment.fileName), attachment.key.count == 32,
                      attachment.byteCount >= 0, attachment.byteCount <= maximumAttachmentBytes else {
                    throw VaultError.invalidPayload
                }
            }
        }
    }

    static func seal(_ payload: VaultPayload, key: SymmetricKey, header: Header) throws -> Data {
        try validate(header)
        try validatePayload(payload)
        var plaintext = try JSONEncoder().encode(payload)
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        guard plaintext.count <= maximumPlaintextBytes else { throw VaultError.dataTooLarge }
        let box = try AES.GCM.seal(plaintext, using: key,
                                   nonce: AES.GCM.Nonce(), authenticating: associatedData(header))
        let envelope = Envelope(header: header, nonce: Data(box.nonce),
                                ciphertext: box.ciphertext, tag: box.tag)
        let data = try JSONEncoder().encode(envelope)
        guard data.count <= maximumEnvelopeBytes else { throw VaultError.dataTooLarge }
        return data
    }

    static func prepare(_ payload: VaultPayload, password: Data) throws -> Prepared {
        let header = try newHeader()
        let key = try deriveKey(password: password, header: header)
        return Prepared(data: try seal(payload, key: key, header: header), key: key, header: header)
    }

    static func open(_ envelope: Envelope, key: SymmetricKey) throws -> Opened {
        try validate(envelope.header)
        var plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: envelope.nonce),
                                          ciphertext: envelope.ciphertext, tag: envelope.tag)
            plaintext = try AES.GCM.open(box, using: key,
                                        authenticating: associatedData(envelope.header))
        } catch { throw VaultError.invalidPasswordOrCorruptVault }
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        let payload: VaultPayload
        do { payload = try JSONDecoder().decode(VaultPayload.self, from: plaintext) }
        catch { throw VaultError.invalidPayload }
        try validatePayload(payload)
        return Opened(payload: payload, key: key, header: envelope.header)
    }

    static func open(_ data: Data, password: Data) throws -> Opened {
        let envelope = try decodeEnvelope(data)
        return try open(envelope, key: deriveKey(password: password, header: envelope.header))
    }

    static func equalPasswords(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(lhs, rhs) { difference |= a ^ b }
        return difference == 0
    }
}

/// v1: magic, UInt64 vault length, UInt32 blob count, exact vault bytes, then
/// sorted (36-byte UUID, UInt64 length, AES-GCM combined) records; integers are BE.
/// Only ciphertext and opaque IDs leave memory. No filenames or keys are exposed.
enum VaultBackup {
    static let maximumBytes = 512 * 1024 * 1024
    static let magic = Data("uniPass.backup\u{0}v1\u{0}".utf8)

    struct Contents {
        var vault: Data
        var attachments: [UUID: Data]
        var isLegacy = false
    }

    static func checkLimits(bytes: Int, count: Int) throws {
        guard bytes >= 0, bytes <= maximumBytes,
              count >= 0, count <= VaultCrypto.maximumAttachmentCount else { throw VaultError.dataTooLarge }
    }

    static func validate(_ data: Data) throws { _ = try decode(data) }

    static func decode(_ data: Data) throws -> Contents {
        try checkLimits(bytes: data.count, count: 0)
        guard data.starts(with: magic) else {
            _ = try VaultCrypto.decodeEnvelope(data)
            return Contents(vault: data, attachments: [:], isLegacy: true)
        }
        var offset = magic.count
        func take(_ length: Int) throws -> Data {
            guard length >= 0, length <= data.count - offset else { throw VaultError.invalidEnvelope }
            defer { offset += length }
            let start = data.startIndex + offset
            return data.subdata(in: start..<(start + length))
        }
        func integer(_ width: Int, maximum: Int) throws -> Int {
            let bytes = try take(width)
            let value = bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            guard value <= UInt64(maximum) else { throw VaultError.dataTooLarge }
            return Int(value)
        }
        let vaultLength = try integer(8, maximum: VaultCrypto.maximumEnvelopeBytes)
        let count = try integer(4, maximum: VaultCrypto.maximumAttachmentCount)
        let vault = try take(vaultLength)
        _ = try VaultCrypto.decodeEnvelope(vault)
        var blobs: [UUID: Data] = [:]
        for _ in 0..<count {
            guard let text = String(data: try take(36), encoding: .utf8),
                  let id = UUID(uuidString: text), blobs[id] == nil else { throw VaultError.invalidAttachment }
            let length = try integer(8, maximum: VaultCrypto.maximumAttachmentBytes + 28)
            guard length >= 28 else { throw VaultError.invalidAttachment }
            blobs[id] = try take(length)
        }
        guard offset == data.count else { throw VaultError.invalidEnvelope }
        return Contents(vault: vault, attachments: blobs)
    }

    static func encode(_ contents: Contents, preservingContainer: Bool = false) throws -> Data {
        _ = try VaultCrypto.decodeEnvelope(contents.vault)
        try checkLimits(bytes: contents.vault.count, count: contents.attachments.count)
        if contents.attachments.isEmpty && !preservingContainer { return contents.vault }
        var size = magic.count + 12 + contents.vault.count
        for blob in contents.attachments.values {
            guard (28...(VaultCrypto.maximumAttachmentBytes + 28)).contains(blob.count) else {
                throw VaultError.invalidAttachment
            }
            size += 44 + blob.count
            try checkLimits(bytes: size, count: contents.attachments.count)
        }
        var data = magic
        func appendInteger(_ value: Int, width: Int) {
            for index in (0..<width).reversed() { data.append(UInt8(truncatingIfNeeded: UInt64(value) >> (index * 8))) }
        }
        appendInteger(contents.vault.count, width: 8)
        appendInteger(contents.attachments.count, width: 4)
        data.append(contents.vault)
        for id in contents.attachments.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            let blob = contents.attachments[id]!
            data.append(Data(id.uuidString.utf8))
            appendInteger(blob.count, width: 8)
            data.append(blob)
        }
        return data
    }

    static func authenticate(_ contents: Contents, payload: VaultPayload) throws {
        let expected = Set(payload.entries.flatMap { $0.attachments.map(\.id) })
        guard expected == Set(contents.attachments.keys) else { throw VaultError.invalidAttachment }
        for entry in payload.entries {
            for attachment in entry.attachments {
                var plaintext = try VaultCrypto.openAttachment(contents.attachments[attachment.id]!,
                    entryID: entry.id, attachment: attachment)
                plaintext.resetBytes(in: 0..<plaintext.count)
            }
        }
    }

    static func collect(vault: Data, payload: VaultPayload, at url: URL) throws -> Data {
        var contents = Contents(vault: vault, attachments: [:])
        var size = magic.count + 12 + vault.count
        for entry in payload.entries {
            for attachment in entry.attachments {
                size += 44 + Int(attachment.byteCount) + 28
                try checkLimits(bytes: size, count: contents.attachments.count + 1)
                contents.attachments[attachment.id] = try VaultAttachmentDisk.readBlob(attachment.id, vault: url)
            }
        }
        try authenticate(contents, payload: payload)
        return try encode(contents)
    }

    /// Same-directory exclusive rename publishes only flushed, private ciphertext.
    /// Unlike VaultDisk this accepts a full backup, but never replaces any target.
    static func write(_ data: Data, to url: URL) throws {
        try validate(data)
        guard url.isFileURL else { throw VaultError.unsafeAttachmentPath }
        try VaultAttachmentDisk.component(url.lastPathComponent)
        let directory = url.deletingLastPathComponent()
        var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
        #if !targetEnvironment(macCatalyst)
        attributes[.protectionKey] = FileProtectionType.complete
        #endif
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: attributes)
        let parent = try VaultAttachmentDisk.directory(directory)
        defer { Darwin.close(parent) }
        let temporary = ".unipass-backup-\(UUID().uuidString).tmp"
        let fd = Darwin.openat(parent, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close(); _ = Darwin.unlinkat(parent, temporary, 0) }
        #if os(iOS) && !targetEnvironment(macCatalyst) && !targetEnvironment(simulator)
        guard Darwin.fcntl(fd, F_SETPROTECTIONCLASS, Int32(1)) == 0 else { throw POSIXError(.EIO) }
        #endif
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try handle.close()
        guard Darwin.renameatx_np(parent, temporary, parent, url.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
            if errno == EEXIST { throw VaultError.vaultAlreadyExists }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        _ = Darwin.fsync(parent)
    }
}

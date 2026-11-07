import Foundation

struct VaultFolder: Identifiable, Codable, Equatable {
    var id: UUID
    var name: String

    init(id: UUID = UUID(), name: String = "") {
        self.id = id
        self.name = name
    }
}

struct CustomField: Identifiable, Codable, Equatable {
    var id: UUID
    var name: String
    var value: String
    /// Bitwarden field types: 0 text, 1 hidden, 2 boolean, 3 linked.
    var type: Int

    init(id: UUID = UUID(), name: String = "", value: String = "", type: Int = 0) {
        self.id = id
        self.name = name
        self.value = value
        self.type = type
    }
}

/// The key is encoded only inside the encrypted vault payload, never beside the blob.
struct VaultAttachment: Identifiable, Codable, Equatable {
    var id: UUID
    var fileName: String
    var byteCount: Int64
    var key: Data

    init(id: UUID = UUID(), fileName: String, byteCount: Int64, key: Data) {
        self.id = id
        self.fileName = fileName
        self.byteCount = byteCount
        self.key = key
    }
}

struct VaultEntry: Identifiable, Codable, Equatable {
    var id: UUID
    var name: String
    var username: String
    var password: String
    var urls: [String]
    var totp: String
    var notes: String
    var folderID: UUID?
    var favorite: Bool
    var fields: [CustomField]
    var originalJSON: String?
    var attachments: [VaultAttachment]
    var createdAt: Date
    var modifiedAt: Date
    var deletedAt: Date?

    init(id: UUID = UUID(), name: String = "", username: String = "",
         password: String = "", urls: [String] = [], totp: String = "",
         notes: String = "", folderID: UUID? = nil, favorite: Bool = false,
         fields: [CustomField] = [], originalJSON: String? = nil, attachments: [VaultAttachment] = [],
         createdAt: Date = Date(), modifiedAt: Date = Date(), deletedAt: Date? = nil) {
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.urls = urls
        self.totp = totp
        self.notes = notes
        self.folderID = folderID
        self.favorite = favorite
        self.fields = fields
        self.originalJSON = originalJSON
        self.attachments = attachments
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.deletedAt = deletedAt
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, username, password, urls, totp, notes, folderID, favorite, fields
        case originalJSON, attachments, createdAt, modifiedAt, deletedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        username = try c.decode(String.self, forKey: .username)
        password = try c.decode(String.self, forKey: .password)
        urls = try c.decode([String].self, forKey: .urls)
        totp = try c.decode(String.self, forKey: .totp)
        notes = try c.decode(String.self, forKey: .notes)
        folderID = try c.decodeIfPresent(UUID.self, forKey: .folderID)
        favorite = try c.decode(Bool.self, forKey: .favorite)
        fields = try c.decode([CustomField].self, forKey: .fields)
        originalJSON = try c.decodeIfPresent(String.self, forKey: .originalJSON)
        attachments = try c.decodeIfPresent([VaultAttachment].self, forKey: .attachments) ?? []
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        modifiedAt = try c.decode(Date.self, forKey: .modifiedAt)
        deletedAt = try c.decodeIfPresent(Date.self, forKey: .deletedAt)
    }
}

struct VaultPayload: Codable {
    var entries: [VaultEntry]
    var folders: [VaultFolder]

    init(entries: [VaultEntry] = [], folders: [VaultFolder] = []) {
        self.entries = entries
        self.folders = folders
    }
}

/// Errors deliberately never include passwords, plaintext, or raw imported data.
enum VaultError: LocalizedError {
    case locked, busy, operationCancelled, vaultAlreadyExists, vaultNotFound
    case emptyPassword, passwordTooLong, invalidPasswordOrCorruptVault
    case unsupportedFormat, invalidEnvelope, invalidPayload, dataTooLarge
    case invalidImport, encryptedImport, entryNotFound, folderNotFound, invalidFolderName
    case randomnessFailed, derivationFailed, biometricsUnavailable
    case externalChange, locationUnavailable
    case mobileEditingDisabled, attachmentNotFound, invalidAttachment, unsafeAttachmentPath
    case attachmentImportFailed
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .mobileEditingDisabled: return "This device is read-only. Enable mobile editing first."
        case .attachmentNotFound: return "The attachment does not exist or its file is missing."
        case .invalidAttachment: return "The attachment metadata is invalid or its ciphertext is corrupted."
        case .unsafeAttachmentPath: return "The attachment path is unsafe; symbolic links and path traversal are not allowed."
        case .attachmentImportFailed: return "Attachments are missing, ambiguous, or unsupported. No data was imported."
        case .externalChange: return "The disk vault changed or is temporarily unreadable, so overwriting was refused. Keep unsaved content, lock the vault, and unlock it again to load the latest version."
        case .locationUnavailable: return "The vault directory is unavailable. Check that the cloud file is downloaded locally and choose the directory again."
        case .locked: return "The vault is locked."
        case .busy: return "Another vault operation is in progress."
        case .operationCancelled: return "The operation was cancelled because the session was locked or changed."
        case .vaultAlreadyExists: return "A vault already exists and cannot be overwritten during creation."
        case .vaultNotFound: return "Vault not found."
        case .emptyPassword: return "The master password cannot be empty."
        case .passwordTooLong: return "The UTF-8 encoding of the master password cannot exceed 4096 bytes."
        case .invalidPasswordOrCorruptVault: return "The master password is incorrect or the vault is corrupted."
        case .unsupportedFormat: return "This vault version or encryption algorithm is not supported."
        case .invalidEnvelope: return "The vault encryption envelope is invalid."
        case .invalidPayload: return "The vault contents are invalid, such as duplicate IDs or an invalid folder reference."
        case .dataTooLarge: return "The data exceeds the vault's safe size limit."
        case .invalidImport: return "This is not a valid unencrypted Bitwarden JSON export."
        case .encryptedImport: return "Encrypted or password-protected Bitwarden exports are unsupported. Export unencrypted JSON first."
        case .entryNotFound: return "Entry not found."
        case .folderNotFound: return "Folder not found."
        case .invalidFolderName: return "The folder name cannot be empty."
        case .randomnessFailed: return "Secure random data could not be generated."
        case .derivationFailed: return "Key derivation failed."
        case .biometricsUnavailable: return "This device does not support the required biometric and device passcode protection."
        case .keychain(let status): return "A secure Keychain operation failed (\(status))."
        }
    }
}

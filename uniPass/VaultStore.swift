import Foundation
import Combine
import CryptoKit
import Security
import LocalAuthentication
import Darwin

/// Coordinates local/file-provider access; the expected ciphertext prevents stale
/// sessions from replacing a file changed by another process.
enum VaultDisk {
    static func read(_ url: URL) throws -> Data {
        try coordinate(url, writing: false) { coordinatedURL in
            let file = try FileHandle(forReadingFrom: coordinatedURL)
            defer { try? file.close() }
            let data = try file.read(upToCount: VaultCrypto.maximumEnvelopeBytes + 1) ?? Data()
            guard data.count <= VaultCrypto.maximumEnvelopeBytes else { throw VaultError.dataTooLarge }
            return data
        }
    }

    static func write(_ data: Data, to url: URL, creating: Bool, expected: Data?) throws {
        guard data.count <= VaultCrypto.maximumEnvelopeBytes else { throw VaultError.dataTooLarge }
        let manager = FileManager.default
        let directory = url.deletingLastPathComponent()
        var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
        #if !targetEnvironment(macCatalyst)
        attributes[.protectionKey] = FileProtectionType.complete
        #endif
        try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: attributes)
        try coordinate(url, writing: true) { destination in
            if !creating {
                guard let expected, let current = try? uncoordinatedRead(destination), current == expected else {
                    throw VaultError.externalChange
                }
            }
            let temporary = destination.deletingLastPathComponent().appendingPathComponent(".unipass-\(UUID().uuidString).tmp")
            let descriptor = temporary.path.withCString { Darwin.open($0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600) }
            guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            defer { try? handle.close(); try? manager.removeItem(at: temporary) }
            #if !targetEnvironment(macCatalyst)
            try manager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: temporary.path)
            #endif
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
            // Check again immediately before committing. Cloud synchronization is
            // still not a distributed lock; offline concurrent edits may conflict.
            if !creating {
                guard let expected, let current = try? uncoordinatedRead(destination), current == expected else {
                    throw VaultError.externalChange
                }
            }
            let result = temporary.path.withCString { source in
                destination.path.withCString { target in
                    creating ? Darwin.renamex_np(source, target, UInt32(RENAME_EXCL)) : Darwin.rename(source, target)
                }
            }
            guard result == 0 else {
                let code = errno
                if creating && code == EEXIST { throw VaultError.vaultAlreadyExists }
                throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
            }
            let directoryDescriptor = directory.path.withCString { Darwin.open($0, O_RDONLY) }
            if directoryDescriptor >= 0 { _ = Darwin.fsync(directoryDescriptor); _ = Darwin.close(directoryDescriptor) }
        }
    }

    private static func uncoordinatedRead(_ url: URL) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: VaultCrypto.maximumEnvelopeBytes + 1) ?? Data()
        guard data.count <= VaultCrypto.maximumEnvelopeBytes else { throw VaultError.dataTooLarge }
        return data
    }

    private static func coordinate<T>(_ url: URL, writing: Bool, action: (URL) throws -> T) throws -> T {
        let coordinator = NSFileCoordinator()
        var coordinationError: NSError?
        var result: Result<T, Error>?
        if writing {
            coordinator.coordinate(writingItemAt: url, options: .forReplacing, error: &coordinationError) { coordinatedURL in
                result = Result { try action(coordinatedURL) }
            }
        } else {
            coordinator.coordinate(readingItemAt: url, options: [], error: &coordinationError) { coordinatedURL in
                result = Result { try action(coordinatedURL) }
            }
        }
        if let coordinationError { throw coordinationError }
        guard let result else { throw CocoaError(.fileReadUnknown) }
        return try result.get()
    }
}

/// Descriptor-relative I/O keeps a checked directory pinned, including against
/// symlink replacement between validation and read/write/unlink. Never stores plaintext.
enum VaultAttachmentDisk {
    static func component(_ name: String) throws {
        guard VaultCrypto.validAttachmentFileName(name) else { throw VaultError.unsafeAttachmentPath }
    }

    static func directory(_ url: URL) throws -> Int32 {
        guard url.isFileURL, !url.pathComponents.contains(".."),
              !url.pathComponents.contains(".") else { throw VaultError.unsafeAttachmentPath }
        // Only expand Darwin's OS-owned aliases, not arbitrary user symlinks.
        // Open the full path once: sandbox grants need not allow opening ancestors.
        let parts = Array(url.pathComponents.dropFirst())
        for part in parts { try component(part) }
        let path = (parts.first == "var" || parts.first == "tmp") ? "/private" + url.path : url.path
        let fd = path.withCString { Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC) }
        guard fd >= 0 else { throw VaultError.unsafeAttachmentPath }
        return fd
    }

    static func read(_ url: URL, maximum: Int) throws -> Data {
        guard url.isFileURL, !url.pathComponents.contains(".."),
              !url.pathComponents.contains(".") else { throw VaultError.unsafeAttachmentPath }
        try component(url.lastPathComponent)
        let parent = try directory(url.deletingLastPathComponent())
        defer { Darwin.close(parent) }
        let fd = Darwin.openat(parent, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw VaultError.attachmentNotFound }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw VaultError.unsafeAttachmentPath
        }
        guard info.st_size >= 0, info.st_size <= Int64(maximum) else { throw VaultError.dataTooLarge }
        let data = try handle.read(upToCount: maximum + 1) ?? Data()
        guard data.count <= maximum else { throw VaultError.dataTooLarge }
        guard Int64(data.count) == info.st_size else { throw VaultError.invalidAttachment }
        return data
    }

    static func children(_ url: URL) throws -> [(name: String, isDirectory: Bool, size: Int64)] {
        let fd = try directory(url)
        guard let stream = Darwin.fdopendir(fd) else { Darwin.close(fd); throw VaultError.unsafeAttachmentPath }
        defer { Darwin.closedir(stream) }
        var result: [(name: String, isDirectory: Bool, size: Int64)] = []
        while true {
            errno = 0
            guard let item = Darwin.readdir(stream) else {
                guard errno == 0 else { throw VaultError.unsafeAttachmentPath }
                break
            }
            let capacity = Int(item.pointee.d_namlen) + 1
            let name = withUnsafePointer(to: &item.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: capacity) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            try component(name)
            var info = stat()
            guard Darwin.fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else { throw VaultError.unsafeAttachmentPath }
            let kind = info.st_mode & S_IFMT
            guard kind == S_IFDIR || kind == S_IFREG else { throw VaultError.unsafeAttachmentPath }
            result.append((name, kind == S_IFDIR, Int64(info.st_size)))
            guard result.count <= VaultCrypto.maximumAttachmentCount + 1 else { throw VaultError.dataTooLarge }
        }
        return result.sorted { $0.name < $1.name }
    }

    static func documents(_ vault: URL, create: Bool) throws -> Int32 {
        let parent = try directory(vault.deletingLastPathComponent())
        defer { Darwin.close(parent) }
        if create {
            guard Darwin.mkdirat(parent, "documents", 0o700) == 0 || errno == EEXIST else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        let fd = Darwin.openat(parent, "documents", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw VaultError.unsafeAttachmentPath }
        return fd
    }

    static func blobName(_ id: UUID) -> String { id.uuidString + ".enc" }

    static func readBlob(_ id: UUID, vault: URL) throws -> Data {
        // The generic reader also pins every parent component.
        try read(vault.deletingLastPathComponent().appendingPathComponent("documents")
            .appendingPathComponent(blobName(id)), maximum: VaultCrypto.maximumAttachmentBytes + 28)
    }

    static func writeBlob(_ data: Data, id: UUID, vault: URL) throws {
        let parent = try documents(vault, create: true)
        defer { Darwin.close(parent) }
        let name = blobName(id)
        let fd = Darwin.openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var completed = false
        defer {
            try? handle.close()
            if !completed { _ = Darwin.unlinkat(parent, name, 0) }
        }
        #if os(iOS) && !targetEnvironment(macCatalyst) && !targetEnvironment(simulator)
        // F_SETPROTECTIONCLASS uses class 1 (complete / class A); the public
        // SDK exposes the fcntl command but not the kernel's class-name macros.
        guard Darwin.fcntl(fd, F_SETPROTECTIONCLASS, Int32(1)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        #endif
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try handle.close()
        // Some file providers do not support syncing directory descriptors.
        _ = Darwin.fsync(parent)
        completed = true
    }

    /// Unlike the legacy reader, only an actual ENOENT is absence. In particular,
    /// a dangling symlink, a directory and access failures must not trigger downloads.
    fileprivate static func syncRead(_ id: UUID, parent: Int32) throws -> Data? {
        let fd = Darwin.openat(parent, blobName(id), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            throw VaultError.unsafeAttachmentPath
        }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw VaultError.unsafeAttachmentPath
        }
        let maximum = VaultCrypto.maximumAttachmentBytes + 28
        guard info.st_size >= 0, info.st_size <= Int64(maximum) else { throw VaultError.dataTooLarge }
        let data = try handle.read(upToCount: maximum + 1) ?? Data()
        guard data.count <= maximum else { throw VaultError.dataTooLarge }
        guard Int64(data.count) == info.st_size else { throw VaultError.invalidAttachment }
        return data
    }

    fileprivate static func syncReadBlob(_ id: UUID, vault: URL) throws -> Data? {
        let parent = try directory(vault.deletingLastPathComponent())
        defer { Darwin.close(parent) }
        let documents = Darwin.openat(parent, "documents", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard documents >= 0 else {
            if errno == ENOENT { return nil }
            throw VaultError.unsafeAttachmentPath
        }
        defer { Darwin.close(documents) }
        return try syncRead(id, parent: documents)
    }

    /// Exclusive creation, with identity for rollback that never removes a replacement.
    fileprivate static func syncWrite(_ data: Data, id: UUID, parent: Int32) throws -> stat {
        let name = blobName(id)
        let fd = Darwin.openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        var completed = false
        defer {
            try? handle.close()
            if !completed { syncRollback(id, identity: info, parent: parent) }
        }
        guard Darwin.fstat(fd, &info) == 0 else { throw POSIXError(.EIO) }
        #if os(iOS) && !targetEnvironment(macCatalyst) && !targetEnvironment(simulator)
        guard Darwin.fcntl(fd, F_SETPROTECTIONCLASS, Int32(1)) == 0 else { throw POSIXError(.EIO) }
        #endif
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try handle.close()
        _ = Darwin.fsync(parent)
        completed = true
        return info
    }

    fileprivate static func syncRollback(_ id: UUID, identity: stat, parent: Int32) {
        var current = stat()
        let name = blobName(id)
        if Darwin.fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
           current.st_dev == identity.st_dev, current.st_ino == identity.st_ino,
           (current.st_mode & S_IFMT) == S_IFREG {
            _ = Darwin.unlinkat(parent, name, 0)
            _ = Darwin.fsync(parent)
        }
    }

    static func removeBlob(_ id: UUID, vault: URL) throws {
        let parent = try documents(vault, create: false)
        defer { Darwin.close(parent) }
        let name = blobName(id)
        var info = stat()
        if Darwin.fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return }
            throw VaultError.unsafeAttachmentPath
        }
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw VaultError.unsafeAttachmentPath }
        guard Darwin.unlinkat(parent, name, 0) == 0 else { throw POSIXError(.EIO) }
        _ = Darwin.fsync(parent)
    }
}

/// Only opaque IDs, lengths and vault ciphertext are visible to the coordinator.
/// Actor isolation also makes discard/commit mutually exclusive without unchecked Sendable.
@MainActor
final class VaultSyncVersion {
    var encryptedVault: Data { vault }
    var attachmentIDs: [UUID] { ids }
    fileprivate let vault: Data
    fileprivate let ids: [UUID]
    fileprivate let owner: UUID
    fileprivate let generation: UUID
    fileprivate let storageURL: URL
    fileprivate let snapshot: Data
    fileprivate var opened: VaultCrypto.Opened?
    fileprivate var references: [UUID: (entryID: UUID, attachment: VaultAttachment)]
    fileprivate var staging: VaultSyncStaging?

    func expectedAttachmentBytes(id: UUID) -> Int? {
        references[id].map { Int($0.attachment.byteCount) + 28 }
    }

    fileprivate init(vault: Data, owner: UUID, generation: UUID, url: URL,
                     snapshot: Data, opened: VaultCrypto.Opened, staging: VaultSyncStaging) {
        self.vault = vault
        self.owner = owner
        self.generation = generation
        storageURL = url
        self.snapshot = snapshot
        self.opened = opened
        self.staging = staging
        var references: [UUID: (entryID: UUID, attachment: VaultAttachment)] = [:]
        for entry in opened.payload.entries {
            for attachment in entry.attachments {
                references[attachment.id] = (entry.id, attachment)
            }
        }
        self.references = references
        ids = references.keys.sorted { $0.uuidString < $1.uuidString }
    }
}

/// The descriptor pins the private, OS-local temporary directory for its lifetime.
/// No vault location (which may be a cloud provider) is used for staging.
fileprivate final class VaultSyncStaging {
    let url: URL
    let descriptor: Int32
    var ids = Set<UUID>()

    init() throws {
        var template = Array(FileManager.default.temporaryDirectory
            .appendingPathComponent("unipass-sync-XXXXXX").path.utf8CString)
        guard let path = template.withUnsafeMutableBufferPointer({ buffer in
            Darwin.mkdtemp(buffer.baseAddress!).map { String(cString: $0) }
        }) else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        url = URL(fileURLWithPath: path, isDirectory: true)
        do { descriptor = try VaultAttachmentDisk.directory(url) }
        catch { try? FileManager.default.removeItem(at: url); throw error }
    }

    deinit {
        for id in ids { _ = Darwin.unlinkat(descriptor, VaultAttachmentDisk.blobName(id), 0) }
        _ = Darwin.close(descriptor)
        _ = url.path.withCString { Darwin.rmdir($0) }
    }
}

@MainActor
final class VaultStore: ObservableObject {
    @Published private(set) var payload = VaultPayload()
    @Published private(set) var isUnlocked = false
    @Published private(set) var hasVault: Bool
    @Published var errorMessage: String?
    @Published private(set) var biometricEnabled: Bool
    @Published var allowMobileEditing: Bool {
        didSet {
            preferences.set(allowMobileEditing, forKey: "allowMobileEditing")
            if allowMobileEditing != oldValue { sessionGeneration = UUID() }
        }
    }

    var canEdit: Bool {
        #if targetEnvironment(macCatalyst)
        return true
        #else
        return allowMobileEditing
        #endif
    }

    func requireEditingAllowed() throws {
        guard canEdit else { throw VaultError.mobileEditingDisabled }
    }

    var vaultURL: URL { storageURL }

    @Published private var storageURL: URL
    @Published private(set) var usesCustomLocation = false
    @Published private(set) var locationError: String?
    @Published private(set) var externalChangeMessage: String?
    private let defaultStorageURL: URL
    private let preferences: UserDefaults
    private var scopedDirectory: URL?
    private var diskSnapshot: Data?
    private var sessionGeneration = UUID()
    private let syncOwner = UUID()
    private var checkingDisk = false
    private var biometricAccount: String {
        SHA256.hash(data: Data(storageURL.path.utf8)).map { String(format: "%02x", $0) }.joined()
    }
    var backupDirectory: URL { defaultStorageURL.deletingLastPathComponent().appendingPathComponent("Sync Backups", isDirectory: true) }
    private struct StoredLocation: Codable { let bookmark: Data; let path: String }
    private static let locationKey = "uniPass.vault.directory.v1"
    private var biometricConsentKey: String { "uniPass.biometry.optedIn." + biometricAccount }
    private var sessionKey: SymmetricKey?
    private var sessionHeader: VaultCrypto.Header?
    // Needed for same-password remote vaults with different salts. Never persisted
    // outside the explicitly opted-in, access-controlled Keychain item.
    private var masterPassword: Data?
    private var operationID: UUID?
    private var authenticationContext: LAContext?

    init(vaultURL: URL? = nil, preferences: UserDefaults = .standard) {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
                .appendingPathComponent("Library/Application Support", isDirectory: true)
        let local = (vaultURL ?? base.appendingPathComponent("uniPass", isDirectory: true)
            .appendingPathComponent("vault.unipass")).standardizedFileURL
        defaultStorageURL = local
        self.preferences = preferences
        allowMobileEditing = preferences.bool(forKey: "allowMobileEditing")
        storageURL = local
        hasVault = FileManager.default.fileExists(atPath: local.path)
        biometricEnabled = false
        if vaultURL == nil, let data = preferences.data(forKey: Self.locationKey) {
            usesCustomLocation = true
            hasVault = true
            do {
                let stored = try JSONDecoder().decode(StoredLocation.self, from: data)
                storageURL = URL(fileURLWithPath: stored.path).appendingPathComponent("vault.unipass")
                var stale = false
                let directory = try URL(resolvingBookmarkData: stored.bookmark, options: [.withoutUI],
                                        relativeTo: nil, bookmarkDataIsStale: &stale)
                _ = directory.startAccessingSecurityScopedResource()
                scopedDirectory = directory
                storageURL = directory.appendingPathComponent("vault.unipass").standardizedFileURL
                if stale {
                    let refreshed = try makeStoredLocation(directory)
                    preferences.set(refreshed, forKey: Self.locationKey)
                }
            } catch {
                locationError = "The selected vault directory cannot be accessed. Reauthorize it or check that the cloud file is downloaded locally. \(error.localizedDescription)"
            }
        }
        biometricEnabled = preferences.bool(forKey: biometricConsentKey)
            && VaultBiometricKeychain.contains(account: biometricAccount)
    }

    deinit { scopedDirectory?.stopAccessingSecurityScopedResource() }

    /// Keeps the source file intact. No existing destination is ever overwritten.
    func copyToDirectory(_ directory: URL) throws {
        try requireSession()
        guard locationError == nil else { throw VaultError.locationUnavailable }
        let destination = directory.appendingPathComponent("vault.unipass").standardizedFileURL
        guard destination != storageURL else { return }
        let accessed = directory.startAccessingSecurityScopedResource()
        var adopted = false
        defer { if accessed && !adopted { directory.stopAccessingSecurityScopedResource() } }
        let bookmark = try makeStoredLocation(directory)
        guard let snapshot = diskSnapshot, try readEncryptedFile() == snapshot else {
            markExternalChange()
            throw VaultError.externalChange
        }
        guard !FileManager.default.fileExists(atPath: destination.path) else { throw VaultError.vaultAlreadyExists }
        var copied: [UUID] = []
        do {
            for entry in payload.entries {
                for attachment in entry.attachments {
                    let bytes = try VaultAttachmentDisk.readBlob(attachment.id, vault: storageURL)
                    _ = try VaultCrypto.openAttachment(bytes, entryID: entry.id, attachment: attachment)
                    try VaultAttachmentDisk.writeBlob(bytes, id: attachment.id, vault: destination)
                    copied.append(attachment.id)
                }
            }
            guard try readEncryptedFile() == snapshot else { throw VaultError.externalChange }
            try VaultDisk.write(snapshot, to: destination, creating: true, expected: nil)
        } catch {
            for id in copied { try? VaultAttachmentDisk.removeBlob(id, vault: destination) }
            throw error
        }
        adoptDirectory(directory, bookmark: bookmark, destination: destination)
        preferences.set(false, forKey: biometricConsentKey)
        biometricEnabled = false
        adopted = true
    }

    func openDirectory(_ directory: URL) throws {
        guard operationID == nil else { throw VaultError.busy }
        let accessed = directory.startAccessingSecurityScopedResource()
        var adopted = false
        defer { if accessed && !adopted { directory.stopAccessingSecurityScopedResource() } }
        let destination = directory.appendingPathComponent("vault.unipass").standardizedFileURL
        let bookmark = try makeStoredLocation(directory)
        _ = try VaultCrypto.decodeEnvelope(VaultDisk.read(destination))
        adoptDirectory(directory, bookmark: bookmark, destination: destination)
        adopted = true
    }

    /// Reopens the local default; does not copy, replace or delete either vault.
    func useDefaultDirectory() throws {
        guard operationID == nil else { throw VaultError.busy }
        let exists = FileManager.default.fileExists(atPath: defaultStorageURL.path)
        if exists { _ = try VaultCrypto.decodeEnvelope(VaultDisk.read(defaultStorageURL)) }
        lock()
        scopedDirectory?.stopAccessingSecurityScopedResource()
        scopedDirectory = nil
        preferences.removeObject(forKey: Self.locationKey)
        storageURL = defaultStorageURL
        usesCustomLocation = false
        locationError = nil
        hasVault = exists
        biometricEnabled = preferences.bool(forKey: biometricConsentKey)
            && VaultBiometricKeychain.contains(account: biometricAccount)
    }

    private func makeStoredLocation(_ directory: URL) throws -> Data {
        let values = try directory.resourceValues(forKeys: [.isDirectoryKey])
        guard values.isDirectory == true else { throw VaultError.locationUnavailable }
        let bookmark = try directory.bookmarkData(options: .minimalBookmark, includingResourceValuesForKeys: nil, relativeTo: nil)
        return try JSONEncoder().encode(StoredLocation(bookmark: bookmark, path: directory.path))
    }

    private func adoptDirectory(_ directory: URL, bookmark: Data, destination: URL) {
        lock()
        scopedDirectory?.stopAccessingSecurityScopedResource()
        scopedDirectory = directory
        preferences.set(bookmark, forKey: Self.locationKey)
        storageURL = destination
        usesCustomLocation = true
        locationError = nil
        hasVault = true
        biometricEnabled = preferences.bool(forKey: biometricConsentKey)
            && VaultBiometricKeychain.contains(account: biometricAccount)
    }

    func checkForExternalChanges() async {
        guard isUnlocked, operationID == nil, !checkingDisk, externalChangeMessage == nil,
              let snapshot = diskSnapshot else { return }
        checkingDisk = true
        defer { checkingDisk = false }
        let url = storageURL
        let generation = sessionGeneration
        let result = await Task.detached(priority: .utility) { Result { try VaultDisk.read(url) } }.value
        guard isUnlocked, operationID == nil, sessionGeneration == generation,
              storageURL == url, diskSnapshot == snapshot else { return }
        switch result {
        case .success(let data): if data != snapshot { markExternalChange() }
        case .failure: markExternalChange()
        }
    }

    private func markExternalChange() {
        guard externalChangeMessage == nil else { return }
        var message = "The vault file was changed by synchronization software or another process, or is temporarily unreadable. Writes are paused. Close unsaved edits, then lock and unlock again to load the latest version."
        if let snapshot = diskSnapshot {
            do {
                try FileManager.default.createDirectory(at: backupDirectory, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
                let backup = backupDirectory.appendingPathComponent("external-\(UUID().uuidString).enc")
                let data = try VaultBackup.collect(vault: snapshot, payload: payload, at: storageURL)
                try VaultBackup.write(data, to: backup)
                message += " The last committed version and all attachments were saved in local synchronization backups."
            } catch { message += " The complete local backup failed, possibly because an attachment is missing. No incomplete backup was created; do not discard content that still needs to be preserved in this session." }
        }
        externalChangeMessage = message
    }

    /// Bootstrap must work before the user can reach the editing preference.
    /// Creating an empty vault does not grant permission to mutate its entries.
    func create(password: String) async throws {
        guard !usesCustomLocation else { throw VaultError.vaultNotFound }
        let token = try beginOperation()
        defer { endOperation(token) }
        guard !FileManager.default.fileExists(atPath: storageURL.path) else {
            hasVault = true
            throw VaultError.vaultAlreadyExists
        }
        var secret = try VaultCrypto.passwordData(password)
        defer { secret.resetBytes(in: 0..<secret.count) }
        let prepared = try await Task.detached(priority: .userInitiated) { [secret] in
            try VaultCrypto.prepare(VaultPayload(), password: secret)
        }.value
        try checkOperation(token)
        try resetBiometricAccessForNewVault()
        try persist(prepared.data, creating: true)
        install(payload: VaultPayload(), key: prepared.key, header: prepared.header, password: secret)
    }

    /// First-launch recovery is available without editing consent, like creation.
    /// Preserve the authenticated backup bytes so disk-based sync hashes match
    /// the selected backup, without re-sealing it or granting editing permission.
    func restoreBackup(data: Data, password: String) async throws {
        guard !usesCustomLocation else { throw VaultError.vaultAlreadyExists }
        let token = try beginOperation()
        defer { endOperation(token) }
        guard !isUnlocked else { throw VaultError.busy }
        guard !FileManager.default.fileExists(atPath: storageURL.path) else {
            hasVault = true
            throw VaultError.vaultAlreadyExists
        }
        var secret = try VaultCrypto.passwordData(password)
        defer { secret.resetBytes(in: 0..<secret.count) }
        let url = storageURL
        let restored = try await Task.detached(priority: .userInitiated) { [secret] in
            try Self.openBackup(data, password: secret, at: url)
        }.value
        let opened = restored.opened
        try checkOperation(token)
        // A vault may have appeared while PBKDF2 was running. Do not touch its
        // biometric credentials; creating:true also closes the filesystem race.
        guard !FileManager.default.fileExists(atPath: storageURL.path) else {
            hasVault = true
            throw VaultError.vaultAlreadyExists
        }
        let plan = try attachmentPlan(restored.contents, opened: opened, remappingConflicts: false)
        try resetBiometricAccessForNewVault()
        try checkOperation(token)
        do {
            try installBackupFiles(plan, creating: true)
        } catch VaultError.vaultAlreadyExists {
            hasVault = true
            throw VaultError.vaultAlreadyExists
        }
        install(payload: opened.payload, key: opened.key, header: opened.header, password: secret)
    }

    func unlock(password: String) async throws {
        let token = try beginOperation()
        defer { endOperation(token) }
        guard !isUnlocked else { throw VaultError.busy }
        var secret = try VaultCrypto.passwordData(password)
        defer { secret.resetBytes(in: 0..<secret.count) }
        let data = try readEncryptedFile()
        let opened = try await Task.detached(priority: .userInitiated) { [secret] in
            try VaultCrypto.open(data, password: secret)
        }.value
        try checkOperation(token)
        guard try readEncryptedFile() == data else { throw VaultError.externalChange }
        diskSnapshot = data
        install(payload: opened.payload, key: opened.key, header: opened.header, password: secret)
    }

    func unlockWithBiometrics() async throws {
        let token = try beginOperation()
        defer { endOperation(token) }
        guard !isUnlocked else { throw VaultError.busy }
        guard biometricEnabled else { throw VaultError.biometricsUnavailable }
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        context.touchIDAuthenticationAllowableReuseDuration = 0
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &evaluationError) else {
            throw evaluationError ?? VaultError.biometricsUnavailable
        }
        authenticationContext = context
        let data = try readEncryptedFile()
        let account = biometricAccount
        // SecItemCopyMatching uses this LAContext to perform the access-control
        // challenge. No separate evaluatePolicy call / cached unauthenticated read.
        var secret = try await Task.detached(priority: .userInitiated) {
            try VaultBiometricKeychain.read(account: account, context: context)
        }.value
        defer { secret.resetBytes(in: 0..<secret.count) }
        try checkOperation(token)
        let opened = try await Task.detached(priority: .userInitiated) { [secret] in
            try VaultCrypto.open(data, password: secret)
        }.value
        try checkOperation(token)
        guard try readEncryptedFile() == data else { throw VaultError.externalChange }
        diskSnapshot = data
        install(payload: opened.payload, key: opened.key, header: opened.header, password: secret)
    }

    func setBiometricEnabled(_ enabled: Bool) throws {
        try requireSession()
        if !enabled {
            revokeBiometricConsent()
            try VaultBiometricKeychain.remove(account: biometricAccount)
            return
        }
        guard let secret = masterPassword else { throw VaultError.locked }
        let context = LAContext()
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &evaluationError) else {
            throw evaluationError ?? VaultError.biometricsUnavailable
        }
        // Do not degrade to device-unlocked accessibility on Catalyst or on a
        // device without a passcode. Unsupported protection fails explicitly.
        do {
            try VaultBiometricKeychain.write(secret, account: biometricAccount)
            preferences.set(true, forKey: biometricConsentKey)
            biometricEnabled = true
        } catch {
            revokeBiometricConsent()
            throw error
        }
    }

    func lock() {
        sessionGeneration = UUID()
        diskSnapshot = nil
        externalChangeMessage = nil
        operationID = nil
        authenticationContext?.invalidate()
        authenticationContext = nil
        sessionKey = nil
        sessionHeader = nil
        if var secret = masterPassword {
            masterPassword = nil
            secret.resetBytes(in: 0..<secret.count)
        }
        payload = VaultPayload()
        isUnlocked = false
        errorMessage = nil
    }

    func save(_ entry: VaultEntry) throws {
        try requireSession()
        try requireEditingAllowed()
        var next = payload
        var entry = entry
        entry.modifiedAt = Date()
        if let index = next.entries.firstIndex(where: { $0.id == entry.id }) {
            // An editor may hold an old value while attachments were changed.
            // Attachment metadata is managed exclusively through the attachment APIs.
            entry.attachments = next.entries[index].attachments
            entry.createdAt = next.entries[index].createdAt
            next.entries[index] = entry
        } else {
            guard entry.attachments.isEmpty else { throw VaultError.invalidAttachment }
            next.entries.append(entry)
        }
        try commit(next)
    }

    func addFolder(name: String) throws {
        try requireSession()
        try requireEditingAllowed()
        let name = try validatedFolderName(name)
        var next = payload
        next.folders.append(VaultFolder(name: name))
        try commit(next)
    }

    func renameFolder(id: UUID, name: String) throws {
        try requireSession()
        try requireEditingAllowed()
        let name = try validatedFolderName(name)
        var next = payload
        guard let index = next.folders.firstIndex(where: { $0.id == id }) else { throw VaultError.folderNotFound }
        next.folders[index].name = name
        try commit(next)
    }

    func deleteFolder(id: UUID) throws {
        try requireSession()
        try requireEditingAllowed()
        var next = payload
        guard next.folders.contains(where: { $0.id == id }) else { throw VaultError.folderNotFound }
        next.folders.removeAll { $0.id == id }
        let now = Date()
        for index in next.entries.indices where next.entries[index].folderID == id {
            next.entries[index].folderID = nil
            next.entries[index].modifiedAt = now
        }
        try commit(next)
    }

    func trash(id: UUID) throws {
        try updateEntry(id: id) { entry in
            if entry.deletedAt == nil { entry.deletedAt = Date() }
        }
    }

    func restore(id: UUID) throws {
        try updateEntry(id: id) { $0.deletedAt = nil }
    }

    func permanentlyDelete(id: UUID) throws {
        try requireSession()
        try requireEditingAllowed()
        var next = payload
        guard let entry = next.entries.first(where: { $0.id == id }) else { throw VaultError.entryNotFound }
        next.entries.removeAll { $0.id == id }
        try commit(next)
        cleanupAttachments(entry.attachments)
    }

    @discardableResult
    func importBitwarden(data: Data, attachmentsDirectory: URL? = nil) throws -> Int {
        try requireSession()
        try requireEditingAllowed()
        let accessed = attachmentsDirectory?.startAccessingSecurityScopedResource() ?? false
        defer { if accessed { attachmentsDirectory?.stopAccessingSecurityScopedResource() } }
        let result = try BitwardenImporter.importVault(data: data, into: payload,
            attachmentsDirectory: attachmentsDirectory)
        var next = result.payload
        var written: [UUID] = []
        var totalBytes: Int64 = 0
        do {
            for source in result.attachmentSources {
                guard let index = next.entries.firstIndex(where: { $0.id == source.entryID }) else {
                    throw VaultError.entryNotFound
                }
                var bytes = try VaultAttachmentDisk.read(source.url, maximum: VaultCrypto.maximumAttachmentBytes)
                defer { bytes.resetBytes(in: 0..<bytes.count) }
                totalBytes += Int64(bytes.count)
                guard totalBytes <= VaultCrypto.maximumAttachmentImportBytes else { throw VaultError.dataTooLarge }
                if let present = next.entries[index].attachments.first(where: { $0.fileName == source.fileName }) {
                    var current = try VaultCrypto.openAttachment(
                        VaultAttachmentDisk.readBlob(present.id, vault: storageURL),
                        entryID: source.entryID, attachment: present)
                    defer { current.resetBytes(in: 0..<current.count) }
                    guard current == bytes else { throw VaultError.attachmentImportFailed }
                    continue
                }
                let attachment = try makeAttachment(bytes, name: source.fileName)
                next.entries[index].attachments.append(attachment)
                try VaultCrypto.validatePayload(next)
                let encrypted = try VaultCrypto.sealAttachment(bytes, entryID: source.entryID, attachment: attachment)
                try VaultAttachmentDisk.writeBlob(encrypted, id: attachment.id, vault: storageURL)
                written.append(attachment.id)
            }
            try commit(next)
        } catch {
            for id in written { try? VaultAttachmentDisk.removeBlob(id, vault: storageURL) }
            throw error
        }
        return result.importedCount
    }

    func removeOriginalJSON(id: UUID) throws {
        try updateEntry(id: id) { $0.originalJSON = nil }
    }

    func addAttachment(entryID: UUID, from url: URL) throws {
        try requireSession()
        try requireEditingAllowed()
        guard let index = payload.entries.firstIndex(where: { $0.id == entryID }) else { throw VaultError.entryNotFound }
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        var bytes = try VaultAttachmentDisk.read(url, maximum: VaultCrypto.maximumAttachmentBytes)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        let attachment = try makeAttachment(bytes, name: url.lastPathComponent)
        var next = payload
        next.entries[index].attachments.append(attachment)
        next.entries[index].modifiedAt = Date()
        try VaultCrypto.validatePayload(next)
        let encrypted = try VaultCrypto.sealAttachment(bytes, entryID: entryID, attachment: attachment)
        try VaultAttachmentDisk.writeBlob(encrypted, id: attachment.id, vault: storageURL)
        do { try commit(next) }
        catch { try? VaultAttachmentDisk.removeBlob(attachment.id, vault: storageURL); throw error }
    }

    /// Returns plaintext for viewing/export; never writes plaintext to a temporary file.
    func attachmentData(entryID: UUID, attachmentID: UUID) throws -> Data {
        try requireSession()
        guard let entry = payload.entries.first(where: { $0.id == entryID }) else { throw VaultError.entryNotFound }
        guard let attachment = entry.attachments.first(where: { $0.id == attachmentID }) else {
            throw VaultError.attachmentNotFound
        }
        return try VaultCrypto.openAttachment(VaultAttachmentDisk.readBlob(attachmentID, vault: storageURL),
            entryID: entryID, attachment: attachment)
    }

    func removeAttachment(entryID: UUID, attachmentID: UUID) throws {
        try requireSession()
        try requireEditingAllowed()
        guard let index = payload.entries.firstIndex(where: { $0.id == entryID }) else { throw VaultError.entryNotFound }
        guard let attachment = payload.entries[index].attachments.first(where: { $0.id == attachmentID }) else {
            throw VaultError.attachmentNotFound
        }
        var next = payload
        next.entries[index].attachments.removeAll { $0.id == attachmentID }
        next.entries[index].modifiedAt = Date()
        try commit(next)
        cleanupAttachments([attachment])
    }

    private func makeAttachment(_ bytes: Data, name: String) throws -> VaultAttachment {
        guard VaultCrypto.validAttachmentFileName(name) else { throw VaultError.unsafeAttachmentPath }
        guard bytes.count <= VaultCrypto.maximumAttachmentBytes else { throw VaultError.dataTooLarge }
        return VaultAttachment(fileName: name, byteCount: Int64(bytes.count), key: try VaultCrypto.randomBytes(count: 32))
    }

    private func cleanupAttachments(_ attachments: [VaultAttachment]) {
        // Commit first: cleanup failure must not invalidate existing references or
        // report an already-committed deletion as a failed transaction. No sync GC.
        for attachment in attachments {
            do { try VaultAttachmentDisk.removeBlob(attachment.id, vault: storageURL) }
            catch { errorMessage = "Deletion was saved, but some unreferenced attachment ciphertext could not be cleaned up." }
        }
    }

    /// Pure-vault bytes for WebDAV and concurrency checks. User-facing backups
    /// must use backupData(), which also includes all referenced attachment blobs.
    func encryptedSnapshot() throws -> Data {
        guard isUnlocked, let diskSnapshot else { throw VaultError.locked }
        return diskSnapshot
    }

    /// Preparation does not reserve operationID across PBKDF2 or network waits.
    /// A lock/reopen, location switch, permission revocation or local edit invalidates it.
    func prepareSyncVersion(_ encryptedVault: Data) async throws -> VaultSyncVersion {
        try requireSession()
        guard let snapshot = diskSnapshot, let secret = masterPassword,
              let key = sessionKey, let header = sessionHeader else { throw VaultError.locked }
        let generation = sessionGeneration
        let url = storageURL
        try verifyBackupSnapshot(snapshot)
        let result = await Task.detached(priority: .userInitiated) {
            Result {
                let envelope = try VaultCrypto.decodeEnvelope(encryptedVault)
                return try VaultCrypto.open(envelope, key: envelope.header == header
                    ? key : VaultCrypto.deriveKey(password: secret, header: envelope.header))
            }
        }.value
        try checkSyncBinding(generation: generation, url: url, snapshot: snapshot)
        let opened = try result.get()
        return try VaultSyncVersion(vault: encryptedVault, owner: syncOwner, generation: generation,
            url: url, snapshot: snapshot, opened: opened, staging: VaultSyncStaging())
    }

    private func checkSyncBinding(generation: UUID, url: URL, snapshot: Data) throws {
        guard !Task.isCancelled, isUnlocked, sessionGeneration == generation,
              storageURL == url, diskSnapshot == snapshot else { throw VaultError.operationCancelled }
        try requireSession()
        if locationError != nil { throw VaultError.locationUnavailable }
        try verifyBackupSnapshot(snapshot)
    }

    func validateSyncVersion(_ version: VaultSyncVersion) throws {
        guard version.owner == syncOwner, version.opened != nil, version.staging != nil else {
            throw VaultError.operationCancelled
        }
        try checkSyncBinding(generation: version.generation, url: version.storageURL, snapshot: version.snapshot)
    }

    private func authenticateSyncAttachment(_ data: Data, id: UUID, version: VaultSyncVersion) throws {
        guard let reference = version.references[id] else { throw VaultError.invalidAttachment }
        guard data.count == version.expectedAttachmentBytes(id: id) else { throw VaultError.invalidAttachment }
        var plaintext = try VaultCrypto.openAttachment(data, entryID: reference.entryID,
            attachment: reference.attachment)
        plaintext.resetBytes(in: 0..<plaintext.count)
    }

    func syncAttachmentData(id: UUID, version: VaultSyncVersion) throws -> Data? {
        try validateSyncVersion(version)
        guard version.references[id] != nil, let staging = version.staging else { throw VaultError.invalidAttachment }
        let data = try VaultAttachmentDisk.syncRead(id, parent: staging.descriptor)
            ?? VaultAttachmentDisk.syncReadBlob(id, vault: storageURL)
        if let data { try authenticateSyncAttachment(data, id: id, version: version) }
        return data
    }

    func stageSyncAttachment(_ data: Data, id: UUID, version: VaultSyncVersion) throws {
        try validateSyncVersion(version)
        try authenticateSyncAttachment(data, id: id, version: version)
        guard let staging = version.staging else { throw VaultError.operationCancelled }
        // Staging deliberately does not compare against local: preserving a remote
        // conflict may need a different ciphertext under the same opaque UUID.
        if let existing = try VaultAttachmentDisk.syncRead(id, parent: staging.descriptor) {
            guard existing == data else { throw VaultError.invalidAttachment }
            return
        }
        _ = try VaultAttachmentDisk.syncWrite(data, id: id, parent: staging.descriptor)
        staging.ids.insert(id)
    }

    /// Streams the portable backup format, retaining only one attachment at a time.
    /// The 512 MiB aggregate limit applies here, not to preparation or uploads.
    func preserveSyncVersion(_ version: VaultSyncVersion) throws -> URL {
        try validateSyncVersion(version)
        var size = VaultBackup.magic.count + 12 + version.encryptedVault.count
        for id in version.attachmentIDs {
            guard let bytes = version.expectedAttachmentBytes(id: id) else { throw VaultError.invalidAttachment }
            size += 44 + bytes
        }
        try VaultBackup.checkLimits(bytes: size, count: version.attachmentIDs.count)
        try FileManager.default.createDirectory(at: backupDirectory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let parent = try VaultAttachmentDisk.directory(backupDirectory)
        defer { Darwin.close(parent) }
        let temporary = ".unipass-sync-\(UUID().uuidString).tmp"
        let name = "\(UUID().uuidString).enc"
        let fd = Darwin.openat(parent, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close(); _ = Darwin.unlinkat(parent, temporary, 0) }
        #if os(iOS) && !targetEnvironment(macCatalyst) && !targetEnvironment(simulator)
        guard Darwin.fcntl(fd, F_SETPROTECTIONCLASS, Int32(1)) == 0 else { throw POSIXError(.EIO) }
        #endif
        func integer(_ value: Int, width: Int) -> Data {
            Data((0..<width).reversed().map { UInt8(truncatingIfNeeded: UInt64(value) >> ($0 * 8)) })
        }
        try handle.write(contentsOf: VaultBackup.magic)
        try handle.write(contentsOf: integer(version.encryptedVault.count, width: 8))
        try handle.write(contentsOf: integer(version.attachmentIDs.count, width: 4))
        try handle.write(contentsOf: version.encryptedVault)
        for id in version.attachmentIDs {
            guard let blob = try syncAttachmentData(id: id, version: version) else { throw VaultError.attachmentNotFound }
            try handle.write(contentsOf: Data(id.uuidString.utf8))
            try handle.write(contentsOf: integer(blob.count, width: 8))
            try handle.write(contentsOf: blob)
        }
        try validateSyncVersion(version)
        try handle.synchronize()
        try handle.close()
        guard Darwin.renameatx_np(parent, temporary, parent, name, UInt32(RENAME_EXCL)) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        _ = Darwin.fsync(parent)
        return backupDirectory.appendingPathComponent(name)
    }

    func commitSyncVersion(_ version: VaultSyncVersion) throws {
        try validateSyncVersion(version)
        guard let opened = version.opened, let secret = masterPassword else { throw VaultError.operationCancelled }
        // Full preflight before either a backup or the first local attachment write.
        for id in version.attachmentIDs {
            guard let incoming = try syncAttachmentData(id: id, version: version) else {
                throw VaultError.attachmentNotFound
            }
            if let local = try VaultAttachmentDisk.syncReadBlob(id, vault: storageURL), local != incoming {
                throw VaultError.invalidAttachment
            }
        }
        let replacing = version.encryptedVault != version.snapshot
        if replacing { _ = try preserveBackup() }
        try validateSyncVersion(version)
        var written: [(UUID, stat)] = []
        // Pin the destination for installation and rollback. A same-vault repair
        // cannot back up its missing old blobs, and intentionally skips that step.
        let parent: Int32?
        if version.attachmentIDs.isEmpty { parent = nil }
        else { parent = try VaultAttachmentDisk.documents(storageURL, create: true) }
        defer { if let parent { Darwin.close(parent) } }
        do {
            if let parent {
                for id in version.attachmentIDs {
                    guard let incoming = try syncAttachmentData(id: id, version: version) else {
                        throw VaultError.attachmentNotFound
                    }
                    if let local = try VaultAttachmentDisk.syncRead(id, parent: parent) {
                        guard local == incoming else { throw VaultError.invalidAttachment }
                    } else {
                        let identity = try VaultAttachmentDisk.syncWrite(incoming, id: id, parent: parent)
                        written.append((id, identity))
                    }
                }
            }
            // Reopen through the vault path as well: a replaced documents directory
            // must not publish a vault whose files exist only in our pinned old one.
            for id in version.attachmentIDs {
                guard let local = try VaultAttachmentDisk.syncReadBlob(id, vault: storageURL),
                      let incoming = try syncAttachmentData(id: id, version: version), local == incoming else {
                    throw VaultError.invalidAttachment
                }
                try authenticateSyncAttachment(local, id: id, version: version)
            }
            try validateSyncVersion(version)
            if replacing { try persist(version.encryptedVault) }
        } catch {
            if let parent {
                for (id, identity) in written { VaultAttachmentDisk.syncRollback(id, identity: identity, parent: parent) }
            }
            throw error
        }
        if replacing {
            install(payload: opened.payload, key: opened.key, header: opened.header, password: secret)
        }
    }

    /// Idempotent, even after lock/location changes. Releases keys and payload too.
    func discardSyncVersion(_ version: VaultSyncVersion) {
        version.staging = nil
        version.opened = nil
        version.references.removeAll()
    }

    /// Exports are allowed in read-only mode, but never export a stale session.
    func backupData(for encryptedVault: Data? = nil) throws -> Data {
        try requireSession()
        guard let snapshot = diskSnapshot, let secret = masterPassword,
              let key = sessionKey, let header = sessionHeader else { throw VaultError.locked }
        try verifyBackupSnapshot(snapshot)
        let vault = encryptedVault ?? snapshot
        let envelope = try VaultCrypto.decodeEnvelope(vault)
        let opened = try VaultCrypto.open(envelope, key: envelope.header == header
            ? key : VaultCrypto.deriveKey(password: secret, header: envelope.header))
        let data = try VaultBackup.collect(vault: vault, payload: opened.payload, at: storageURL)
        try verifyBackupSnapshot(snapshot)
        return data
    }

    @discardableResult
    func preserveBackup(_ encryptedVault: Data? = nil) throws -> URL {
        let data = try backupData(for: encryptedVault)
        let url = backupDirectory.appendingPathComponent("\(UUID().uuidString).enc")
        try VaultBackup.write(data, to: url)
        return url
    }

    private func verifyBackupSnapshot(_ snapshot: Data) throws {
        guard (try? readEncryptedFile()) == snapshot else {
            markExternalChange()
            throw VaultError.externalChange
        }
    }

    private nonisolated static func openBackup(_ data: Data, password: Data, at url: URL) throws
        -> (contents: VaultBackup.Contents, opened: VaultCrypto.Opened) {
        var contents = try VaultBackup.decode(data)
        let opened = try VaultCrypto.open(contents.vault, password: password)
        // Old vault-only exports can use local siblings, but may never silently
        // restore dangling references when those siblings are unavailable.
        if contents.isLegacy {
            for entry in opened.payload.entries {
                for attachment in entry.attachments {
                    contents.attachments[attachment.id] = try VaultAttachmentDisk.readBlob(attachment.id, vault: url)
                }
            }
        }
        try VaultBackup.authenticate(contents, payload: opened.payload)
        return (contents, opened)
    }

    private struct BackupInstallation {
        var vault: Data
        var payload: VaultPayload
        var blobs: [UUID: Data]
    }

    private func attachmentPlan(_ contents: VaultBackup.Contents, opened: VaultCrypto.Opened,
                                remappingConflicts: Bool) throws -> BackupInstallation {
        var plan = BackupInstallation(vault: contents.vault, payload: opened.payload, blobs: [:])
        var changed = false
        for entryIndex in plan.payload.entries.indices {
            for attachmentIndex in plan.payload.entries[entryIndex].attachments.indices {
                let entryID = plan.payload.entries[entryIndex].id
                var attachment = plan.payload.entries[entryIndex].attachments[attachmentIndex]
                let blob = contents.attachments[attachment.id]!
                let path = storageURL.deletingLastPathComponent().appendingPathComponent("documents")
                    .appendingPathComponent(VaultAttachmentDisk.blobName(attachment.id))
                var info = stat()
                let (status, code) = path.path.withCString { name -> (Int32, Int32) in
                    let result = Darwin.lstat(name, &info)
                    return (result, errno)
                }
                if status == 0 {
                    if (try? VaultAttachmentDisk.readBlob(attachment.id, vault: storageURL)) == blob { continue }
                    guard remappingConflicts else { throw VaultError.invalidAttachment }
                    var plaintext = try VaultCrypto.openAttachment(blob, entryID: entryID, attachment: attachment)
                    defer { plaintext.resetBytes(in: 0..<plaintext.count) }
                    attachment.id = UUID()
                    plan.blobs[attachment.id] = try VaultCrypto.sealAttachment(plaintext, entryID: entryID, attachment: attachment)
                    plan.payload.entries[entryIndex].attachments[attachmentIndex] = attachment
                    changed = true
                } else {
                    guard code == ENOENT else { throw VaultError.unsafeAttachmentPath }
                    plan.blobs[attachment.id] = blob
                }
            }
        }
        if changed { plan.vault = try VaultCrypto.seal(plan.payload, key: opened.key, header: opened.header) }
        return plan
    }

    private func installBackupFiles(_ plan: BackupInstallation, creating: Bool) throws {
        // A brand-new restore may not even have a vault parent yet.
        try FileManager.default.createDirectory(at: storageURL.deletingLastPathComponent(),
            withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var written: [UUID] = []
        do {
            for (id, blob) in plan.blobs {
                try VaultAttachmentDisk.writeBlob(blob, id: id, vault: storageURL)
                written.append(id)
            }
            try persist(plan.vault, creating: creating)
        } catch {
            for id in written { try? VaultAttachmentDisk.removeBlob(id, vault: storageURL) }
            throw error
        }
    }

    func restoreBackupIntoCurrent(_ data: Data) async throws {
        try requireSession()
        try requireEditingAllowed()
        guard let secret = masterPassword, let snapshot = diskSnapshot else { throw VaultError.locked }
        // This must succeed completely before any incoming files can be installed.
        _ = try preserveBackup()
        let generation = sessionGeneration
        let url = storageURL
        let token = try beginOperation()
        defer { endOperation(token) }
        let restored = try await Task.detached(priority: .userInitiated) {
            try Self.openBackup(data, password: secret, at: url)
        }.value
        try checkOperation(token)
        guard isUnlocked, sessionGeneration == generation, storageURL == url,
              diskSnapshot == snapshot else { throw VaultError.operationCancelled }
        try requireEditingAllowed()
        try verifyBackupSnapshot(snapshot)
        let plan = try attachmentPlan(restored.contents, opened: restored.opened, remappingConflicts: true)
        try checkOperation(token)
        try installBackupFiles(plan, creating: false)
        install(payload: plan.payload, key: restored.opened.key, header: restored.opened.header, password: secret)
    }

    func encryptedData() throws -> Data {
        try requireSession()
        guard let key = sessionKey, let header = sessionHeader else { throw VaultError.locked }
        return try VaultCrypto.seal(payload, key: key, header: header)
    }

    /// Compatibility API: different-salt PBKDF2 blocks the caller. Prefer the
    /// asynchronous alternative below when invoking replacement from the UI.
    func replaceEncryptedVault(_ data: Data) throws {
        try requireSession()
        guard let secret = masterPassword, let header = sessionHeader, let key = sessionKey else {
            throw VaultError.locked
        }
        let envelope = try VaultCrypto.decodeEnvelope(data)
        let opened = try VaultCrypto.open(envelope, key: envelope.header == header
            ? key : VaultCrypto.deriveKey(password: secret, header: envelope.header))
        try persist(data)
        install(payload: opened.payload, key: opened.key, header: opened.header, password: secret)
    }

    func replaceEncryptedVaultAsync(_ data: Data) async throws {
        try requireSession()
        guard let secret = masterPassword else { throw VaultError.locked }
        let token = try beginOperation()
        defer { endOperation(token) }
        let opened = try await Task.detached(priority: .userInitiated) {
            try VaultCrypto.open(data, password: secret)
        }.value
        try checkOperation(token)
        try persist(data)
        install(payload: opened.payload, key: opened.key, header: opened.header, password: secret)
    }

    func changePassword(current: String, new: String) async throws {
        try requireSession()
        try requireEditingAllowed()
        guard let secret = masterPassword else { throw VaultError.locked }
        var currentSecret = try VaultCrypto.passwordData(current)
        defer { currentSecret.resetBytes(in: 0..<currentSecret.count) }
        guard VaultCrypto.equalPasswords(secret, currentSecret) else {
            throw VaultError.invalidPasswordOrCorruptVault
        }
        var newSecret = try VaultCrypto.passwordData(new)
        defer { newSecret.resetBytes(in: 0..<newSecret.count) }
        let token = try beginOperation()
        defer { endOperation(token) }
        let snapshot = payload
        let prepared = try await Task.detached(priority: .userInitiated) { [newSecret] in
            try VaultCrypto.prepare(snapshot, password: newSecret)
        }.value
        try checkOperation(token)
        try requireEditingAllowed()
        try persist(prepared.data)
        install(payload: snapshot, key: prepared.key, header: prepared.header, password: newSecret)
        if biometricEnabled {
            // The file is already committed: never report password change as
            // failed just because the optional Keychain refresh failed.
            do {
                try VaultBiometricKeychain.write(newSecret, account: biometricAccount)
            } catch {
                let updateError = error
                revokeBiometricConsent()
                do {
                    try VaultBiometricKeychain.remove(account: biometricAccount)
                    biometricEnabled = false
                    errorMessage = "The master password changed, but biometric access could not be updated and was disabled: \(updateError.localizedDescription)"
                } catch {
                    biometricEnabled = false
                    errorMessage = "The master password changed and biometrics were disabled, but the old Keychain item could not be removed: \(error.localizedDescription)"
                }
            }
        }
    }

    private func revokeBiometricConsent() {
        preferences.set(false, forKey: biometricConsentKey)
        biometricEnabled = false
    }

    private func resetBiometricAccessForNewVault() throws {
        // A stale Keychain item alone must never opt a new or restored vault in.
        // Consent is device-local metadata, contains no secret, and is required
        // in addition to the Keychain's biometric access control.
        revokeBiometricConsent()
        do {
            try VaultBiometricKeychain.remove(account: biometricAccount)
        } catch VaultError.keychain(let status) where status == errSecMissingEntitlement {
            // Local-run signing may have no Keychain access group. Such an item
            // cannot be used here; requiring its deletion would block recovery.
            // Explicitly enabling biometrics later must replace the protected item.
        }
    }

    private func beginOperation() throws -> UUID {
        if locationError != nil { throw VaultError.locationUnavailable }
        guard operationID == nil else { throw VaultError.busy }
        let token = UUID()
        operationID = token
        errorMessage = nil
        return token
    }

    private func checkOperation(_ token: UUID) throws {
        guard operationID == token, !Task.isCancelled else { throw VaultError.operationCancelled }
    }

    private func endOperation(_ token: UUID) {
        guard operationID == token else { return }
        operationID = nil
        authenticationContext?.invalidate()
        authenticationContext = nil
    }

    private func requireSession() throws {
        if externalChangeMessage != nil {
            if let snapshot = diskSnapshot, (try? VaultDisk.read(storageURL)) == snapshot {
                externalChangeMessage = nil
            } else { throw VaultError.externalChange }
        }
        guard isUnlocked, sessionKey != nil, masterPassword != nil else { throw VaultError.locked }
        guard operationID == nil else { throw VaultError.busy }
    }

    private func install(payload: VaultPayload, key: SymmetricKey,
                         header: VaultCrypto.Header, password: Data) {
        masterPassword = password
        sessionKey = key
        sessionHeader = header
        self.payload = payload
        hasVault = true
        isUnlocked = true
        errorMessage = nil
    }

    private func commit(_ next: VaultPayload) throws {
        guard let key = sessionKey, let header = sessionHeader else { throw VaultError.locked }
        let data = try VaultCrypto.seal(next, key: key, header: header)
        try persist(data)
        payload = next
    }

    private func updateEntry(id: UUID, change: (inout VaultEntry) -> Void) throws {
        try requireSession()
        try requireEditingAllowed()
        var next = payload
        guard let index = next.entries.firstIndex(where: { $0.id == id }) else { throw VaultError.entryNotFound }
        change(&next.entries[index])
        next.entries[index].modifiedAt = Date()
        try commit(next)
    }

    private func validatedFolderName(_ name: String) throws -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultError.invalidFolderName }
        return trimmed
    }

    private func readEncryptedFile() throws -> Data {
        if locationError != nil { throw VaultError.locationUnavailable }
        // A missing cloud file must never turn into a new empty vault silently.
        guard FileManager.default.fileExists(atPath: storageURL.path) else {
            if !usesCustomLocation { hasVault = false }
            throw VaultError.vaultNotFound
        }
        return try VaultDisk.read(storageURL)
    }

    private func persist(_ data: Data, creating: Bool = false) throws {
        if locationError != nil { throw VaultError.locationUnavailable }
        do {
            try VaultDisk.write(data, to: storageURL, creating: creating, expected: diskSnapshot)
            diskSnapshot = data
        } catch VaultError.externalChange {
            markExternalChange()
            throw VaultError.externalChange
        }
    }
}

/// Data-protection Keychain is required on Catalyst too. There is intentionally
/// no login-keychain / user-presence / passcode-only fallback.
private enum VaultBiometricKeychain {
    private static var service: String { (Bundle.main.bundleIdentifier ?? "com.unipass.unipass") + ".vault.biometry.v1" }

    private static func query(account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false,
         kSecUseDataProtectionKeychain as String: true]
    }

    static func contains(account: String) -> Bool {
        var request = query(account: account)
        request[kSecReturnAttributes as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        let context = LAContext()
        context.interactionNotAllowed = true
        request[kSecUseAuthenticationContext as String] = context
        let status = SecItemCopyMatching(request as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    static func write(_ password: Data, account: String) throws {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error) else {
            if let error = error { throw error.takeRetainedValue() as Error }
            throw VaultError.biometricsUnavailable
        }
        // Remove/add avoids an update that could require synchronously prompting
        // for the old item's biometrics. If add fails, it remains disabled.
        try remove(account: account)
        var request = query(account: account)
        request[kSecAttrAccessControl as String] = access
        request[kSecValueData as String] = password
        let context = LAContext()
        context.interactionNotAllowed = true
        request[kSecUseAuthenticationContext as String] = context
        let status = SecItemAdd(request as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
    }

    static func read(account: String, context: LAContext) throws -> Data {
        var request = query(account: account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        request[kSecUseAuthenticationContext as String] = context
        context.localizedReason = "Unlock the uniPass vault"
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
        guard let password = result as? Data else { throw VaultError.invalidEnvelope }
        return password
    }

    static func remove(account: String) throws {
        var request = query(account: account)
        let context = LAContext()
        context.interactionNotAllowed = true
        request[kSecUseAuthenticationContext as String] = context
        let status = SecItemDelete(request as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultError.keychain(status) }
    }
}

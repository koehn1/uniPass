import Foundation
import Combine
import CryptoKit

enum SyncBackend: String, CaseIterable, Codable {
    case webDAV, s3
}

@MainActor
final class SyncCoordinator: ObservableObject {
    @Published var configuration = WebDAVConfiguration() {
        didSet { if backend == .webDAV, oldValue != configuration { configurationChanged() } }
    }
    @Published var backend: SyncBackend = .webDAV {
        didSet { if oldValue != backend { configurationChanged() } }
    }
    @Published var s3Configuration = S3Configuration() {
        didSet { if backend == .s3, oldValue != s3Configuration { configurationChanged() } }
    }
    @Published private(set) var busy = false
    @Published var message: String?
    @Published private(set) var hasConflict = false
    @Published private(set) var lastSync: Date?
    private var pending: WebDAVDownload?
    private var pendingVersion: VaultSyncVersion?
    private weak var pendingStore: VaultStore?
    private var pendingConfiguration: ClientConfiguration?
    private var operation = UUID()
    private var activeTask: Task<Void, Never>?
    private var activeVaultPath = ""
    private let defaults: UserDefaults
    private let makeClient: (WebDAVConfiguration) throws -> any WebDAVServing
    private let makeS3Client: (S3Configuration) throws -> any WebDAVServing

    private enum ClientConfiguration: Equatable {
        case webDAV(WebDAVConfiguration)
        case s3(S3Configuration)
    }

    private struct Baseline: Codable {
        let localHash: String
        let remoteHash: String
        let date: Date
    }

    init(defaults: UserDefaults = .standard,
         makeClient: @escaping (WebDAVConfiguration) throws -> any WebDAVServing = { try WebDAVClient(configuration: $0) },
         makeS3Client: @escaping (S3Configuration) throws -> any WebDAVServing = { try S3Client(configuration: $0) }) {
        self.defaults = defaults
        self.makeClient = makeClient
        self.makeS3Client = makeS3Client
    }

    private var selectedConfiguration: ClientConfiguration {
        switch backend {
        case .webDAV: return .webDAV(configuration)
        case .s3: return .s3(s3Configuration)
        }
    }

    private var baselineKey: String {
        switch backend {
        case .webDAV:
            // Keep the existing key so installed WebDAV baselines need no rewrite.
            return "sync.baseline." + Self.hash(Data((configuration.serverURL + "|" + configuration.username + "|" + activeVaultPath).utf8))
        case .s3:
            let identity = [s3Configuration.endpoint, s3Configuration.bucket, s3Configuration.prefix, activeVaultPath]
            return "sync.baseline.s3." + Self.hash((try? JSONEncoder().encode(identity)) ?? Data())
        }
    }

    private func client(for config: ClientConfiguration) throws -> any WebDAVServing {
        switch config {
        case .webDAV(let value): return try makeClient(value)
        case .s3(let value): return try makeS3Client(value)
        }
    }

    private func validateConfiguration() throws {
        switch backend {
        case .webDAV: _ = try WebDAVClient(configuration: configuration)
        case .s3: _ = try S3Client(configuration: s3Configuration)
        }
    }

    func loadConfiguration(vaultURL: URL? = nil) {
        if let vaultURL { activeVaultPath = vaultURL.standardizedFileURL.path }
        do {
            if let data = try KeychainCredentialStore.load(account: "webdav.configuration") {
                configuration = try JSONDecoder().decode(WebDAVConfiguration.self, from: data)
            }
            if let data = try KeychainCredentialStore.load(account: "s3.configuration") {
                s3Configuration = try JSONDecoder().decode(S3Configuration.self, from: data)
            }
            backend = defaults.string(forKey: "sync.backend").flatMap(SyncBackend.init(rawValue:)) ?? .webDAV
            lastSync = baseline()?.date
        } catch { message = error.localizedDescription }
    }

    func saveConfiguration(persistCredentials: Bool = true) throws {
        try validateConfiguration()
        if persistCredentials {
            switch backend {
            case .webDAV:
                try KeychainCredentialStore.save(JSONEncoder().encode(configuration), account: "webdav.configuration")
            case .s3:
                try KeychainCredentialStore.save(JSONEncoder().encode(s3Configuration), account: "s3.configuration")
            }
        }
        defaults.set(backend.rawValue, forKey: "sync.backend")
        clearConflict()
        lastSync = baseline()?.date
    }

    private func configurationChanged() {
        let wasBusy = busy
        activeTask?.cancel()
        operation = UUID()
        busy = false
        clearConflict()
        lastSync = baseline()?.date
        if wasBusy { message = SyncError.localChanged.localizedDescription }
    }

    func cancelPending() {
        activeTask?.cancel()
        activeTask = nil
        operation = UUID()
        busy = false
        clearConflict()
        configuration.password = ""
        s3Configuration.secretAccessKey = ""
        message = nil
    }

    func clearConflict() {
        if let version = pendingVersion { pendingStore?.discardSyncVersion(version) }
        pending = nil
        pendingVersion = nil
        pendingStore = nil
        pendingConfiguration = nil
        hasConflict = false
    }

    // Own the actual network task, while keeping the public async methods awaitable.
    private func run(_ body: @escaping (UUID, ClientConfiguration) async throws -> Void) async {
        guard !busy else { return }
        busy = true
        let token = UUID()
        operation = token
        let config = selectedConfiguration
        let task = Task { @MainActor in
            do {
                try self.check(token, configuration: config)
                try await body(token, config)
            }
            catch { if self.operation == token { self.message = error.localizedDescription } }
            if self.operation == token { self.busy = false; self.activeTask = nil }
        }
        activeTask = task
        await withTaskCancellationHandler(operation: { await task.value }, onCancel: { task.cancel() })
    }

    func testConnection() async {
        await run { token, config in
            let client = try self.client(for: config)
            try await client.testConnection()
            try self.check(token, configuration: config)
            self.message = "Connection succeeded. Remote storage is accessible; write access will be verified during synchronization."
        }
    }

    func synchronize(store: VaultStore) async {
        guard !busy, store.isUnlocked else { return }
        activeVaultPath = store.vaultURL.standardizedFileURL.path
        lastSync = baseline()?.date
        await run { token, config in
            // Session-only credentials must not require a provisioned Keychain group.
            try self.validateConfiguration()
            self.clearConflict()
            let client = try self.client(for: config)
            let local = try await store.prepareSyncVersion(self.localData(store))
            defer { if self.pendingVersion !== local { store.discardSyncVersion(local) } }
            try self.check(token, configuration: config, store: store, version: local)
            let localHash = Self.hash(local.encryptedVault)
            let remote = try await client.download()
            try self.check(token, configuration: config, store: store, version: local)
            guard let remote else {
                guard self.baseline() == nil else { throw SyncError.remoteDeleted }
                try await self.publishAttachments(local, client: client, token: token, config: config, store: store)
                _ = try await client.upload(local.encryptedVault, expectedETag: nil, createOnly: true)
                try self.check(token, configuration: config, store: store, version: local)
                try self.record(store: store, remote: local.encryptedVault)
                self.message = "First upload completed. Use the same master password on other devices."
                return
            }
            let remoteHash = Self.hash(remote.data)
            if localHash == remoteHash {
                try await self.receiveAttachments(local, compareLocal: true, client: client, token: token, config: config, store: store)
                try await self.verifyRemote(remote, client: client, token: token, config: config, store: store, version: local)
                try store.commitSyncVersion(local)
                try self.record(store: store, remote: remote.data)
                self.message = "The vault is up to date; attachments were verified and repaired."
            } else if let previous = self.baseline(), remoteHash == previous.remoteHash {
                try await self.publishAttachments(local, client: client, token: token, config: config, store: store)
                _ = try await client.upload(local.encryptedVault, expectedETag: remote.etag, createOnly: false)
                try self.check(token, configuration: config, store: store, version: local)
                try self.record(store: store, remote: local.encryptedVault)
                self.message = "Local changes were uploaded safely."
            } else if self.baseline()?.localHash == localHash ||
                        (self.baseline() == nil && store.payload.entries.isEmpty && store.payload.folders.isEmpty) {
                try await self.receive(remote, client: client, token: token, config: config, store: store, local: local)
                self.message = "Remote changes were downloaded. The previous version was saved as a local encrypted backup."
            } else {
                self.pending = remote
                self.pendingVersion = local
                self.pendingStore = store
                self.pendingConfiguration = config
                self.hasConflict = true
                self.message = "The local and remote versions differ; no data was overwritten. Choose which version to keep. Automatic item-by-item merging is unsupported."
            }
        }
    }

    func resolve(useRemote: Bool, store: VaultStore) async {
        guard !busy, let remote = pending, let local = pendingVersion,
              pendingStore === store, let config = pendingConfiguration else { return }
        await run { token, selected in
            defer { if self.pendingVersion === local { self.clearConflict() } }
            guard selected == config else { throw SyncError.localChanged }
            try self.check(token, configuration: config, store: store, version: local)
            let client = try self.client(for: config)
            try await self.verifyRemote(remote, client: client, token: token, config: config, store: store, version: local)
            if useRemote {
                try await self.receive(remote, client: client, token: token, config: config, store: store, local: local)
            } else {
                let incoming = try await store.prepareSyncVersion(remote.data)
                defer { store.discardSyncVersion(incoming) }
                try self.check(token, configuration: config, store: store, version: local)
                try await self.receiveAttachments(incoming, client: client, token: token, config: config, store: store)
                try await self.verifyRemote(remote, client: client, token: token, config: config, store: store, version: incoming)
                _ = try store.preserveSyncVersion(incoming)
                try await self.publishAttachments(local, client: client, token: token, config: config, store: store)
                _ = try await client.upload(local.encryptedVault, expectedETag: remote.etag, createOnly: false)
                try self.check(token, configuration: config, store: store, version: local)
                try self.record(store: store, remote: local.encryptedVault)
            }
            self.message = "The conflict was resolved. The replaced version was saved as a local encrypted backup."
        }
    }

    private func receive(_ remote: WebDAVDownload, client: any WebDAVServing, token: UUID,
                         config: ClientConfiguration, store: VaultStore, local: VaultSyncVersion) async throws {
        let incoming = try await store.prepareSyncVersion(remote.data)
        defer { store.discardSyncVersion(incoming) }
        try check(token, configuration: config, store: store, version: local)
        try await receiveAttachments(incoming, client: client, token: token, config: config, store: store)
        try await verifyRemote(remote, client: client, token: token, config: config, store: store, version: incoming)
        try store.commitSyncVersion(incoming)
        // Commit intentionally changes the store generation; do not validate the old version afterwards.
        try record(store: store, remote: remote.data)
    }

    private func publishAttachments(_ version: VaultSyncVersion, client: any WebDAVServing,
                                    token: UUID, config: ClientConfiguration, store: VaultStore) async throws {
        for id in version.attachmentIDs {
            try check(token, configuration: config, store: store, version: version)
            guard let data = try store.syncAttachmentData(id: id, version: version) else {
                throw SyncError.attachmentMissing(id)
            }
            let remote = try await client.downloadAttachment(id: id)
            try check(token, configuration: config, store: store, version: version)
            if let remote {
                guard remote.data == data else { throw SyncError.attachmentCollision(id) }
            } else {
                try await createAttachment(data, id: id, version: version, client: client, token: token, config: config, store: store)
            }
        }
    }

    private func receiveAttachments(_ version: VaultSyncVersion, compareLocal: Bool = false,
                                    client: any WebDAVServing, token: UUID, config: ClientConfiguration,
                                    store: VaultStore) async throws {
        for id in version.attachmentIDs {
            try check(token, configuration: config, store: store, version: version)
            let local = compareLocal ? try store.syncAttachmentData(id: id, version: version) : nil
            let remote = try await client.downloadAttachment(id: id)
            try check(token, configuration: config, store: store, version: version)
            if let remote {
                if let local, local != remote.data { throw SyncError.attachmentCollision(id) }
                try store.stageSyncAttachment(remote.data, id: id, version: version)
            } else {
                guard let data = try store.syncAttachmentData(id: id, version: version) else {
                    throw SyncError.attachmentMissing(id)
                }
                try await createAttachment(data, id: id, version: version, client: client, token: token, config: config, store: store)
                try store.stageSyncAttachment(data, id: id, version: version)
            }
        }
    }

    private func createAttachment(_ data: Data, id: UUID, version: VaultSyncVersion,
                                  client: any WebDAVServing, token: UUID, config: ClientConfiguration,
                                  store: VaultStore) async throws {
        do {
            _ = try await client.uploadAttachment(data, id: id)
            try check(token, configuration: config, store: store, version: version)
        } catch {
            try check(token, configuration: config, store: store, version: version)
            // A concurrent create (or a lost successful response) is safe only for identical bytes.
            let existing = try await client.downloadAttachment(id: id)
            try check(token, configuration: config, store: store, version: version)
            guard let existing else { throw error }
            guard existing.data == data else { throw SyncError.attachmentCollision(id) }
        }
    }

    private func verifyRemote(_ expected: WebDAVDownload, client: any WebDAVServing, token: UUID,
                              config: ClientConfiguration, store: VaultStore, version: VaultSyncVersion) async throws {
        let current = try await client.download()
        try check(token, configuration: config, store: store, version: version)
        guard let current, Self.hash(current.data) == Self.hash(expected.data), current.etag == expected.etag else {
            throw SyncError.remoteChanged
        }
    }

    private func check(_ token: UUID, configuration: ClientConfiguration,
                       store: VaultStore? = nil, version: VaultSyncVersion? = nil) throws {
        try Task.checkCancellation()
        guard operation == token else { throw VaultError.operationCancelled }
        guard configuration == selectedConfiguration else { throw SyncError.localChanged }
        if let store, let version {
            guard store.isUnlocked else { throw VaultError.operationCancelled }
            _ = try localData(store)
            // Prepared versions bind both local and remote data to the same local session/snapshot.
            do { try store.validateSyncVersion(version) }
            catch VaultError.operationCancelled { throw SyncError.localChanged }
        }
    }

    private func localData(_ store: VaultStore) throws -> Data {
        guard store.isUnlocked else { throw VaultError.locked }
        let data = try VaultDisk.read(store.vaultURL)
        guard data == (try store.encryptedSnapshot()) else { throw VaultError.externalChange }
        return data
    }

    private func baseline() -> Baseline? {
        guard let data = defaults.data(forKey: baselineKey) else { return nil }
        return try? JSONDecoder().decode(Baseline.self, from: data)
    }

    private func record(store: VaultStore, remote: Data) throws {
        let value = Baseline(localHash: Self.hash(try localData(store)), remoteHash: Self.hash(remote), date: Date())
        defaults.set(try JSONEncoder().encode(value), forKey: baselineKey)
        lastSync = value.date
    }

    private static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

enum SyncError: LocalizedError {
    case localChanged, remoteChanged, remoteDeleted
    case attachmentMissing(UUID), attachmentCollision(UUID)
    var errorDescription: String? {
        switch self {
        case .localChanged: return "Local content or configuration changed during synchronization. Synchronize again."
        case .remoteChanged: return "The remote version changed again. Synchronize again and confirm the conflict."
        case .remoteDeleted: return "The previously synchronized remote file no longer exists. Synchronization stopped to avoid restoring deleted data. Restore a remote backup or use a new synchronization directory."
        case .attachmentMissing(let id): return "Synchronized attachment \(id.uuidString) is missing; the vault was not committed."
        case .attachmentCollision(let id): return "Attachment ciphertext collision for \(id.uuidString); overwriting was refused."
        }
    }
}

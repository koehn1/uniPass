import Foundation
import XCTest
@testable import uniPass

@MainActor
final class SyncAttachmentTests: XCTestCase {
    private let password = "sync-attachment-password"

    private func store(_ environment: SyncTestEnvironment, _ name: String, attached: Bool = false) async throws -> VaultStore {
        let store = VaultStore(vaultURL: environment.directory.appendingPathComponent("\(name)/vault.unipass"),
                               preferences: environment.defaults)
        try await store.create(password: password)
        if attached {
            let entry = VaultEntry(name: name)
            try store.save(entry)
            let source = environment.directory.appendingPathComponent("\(name).txt")
            try Data("private bytes \(name)".utf8).write(to: source)
            try store.addAttachment(entryID: entry.id, from: source)
        }
        return store
    }

    private func coordinator(_ environment: SyncTestEnvironment, _ server: AttachmentSyncServer) -> SyncCoordinator {
        let sync = SyncCoordinator(defaults: environment.defaults, makeClient: { _ in server })
        sync.configuration.serverURL = "https://sync.invalid/existing/"
        return sync
    }

    private func blobURL(_ store: VaultStore, _ id: UUID) -> URL {
        store.vaultURL.deletingLastPathComponent().appendingPathComponent("documents")
            .appendingPathComponent(VaultAttachmentDisk.blobName(id))
    }

    private func baselineValues(_ defaults: UserDefaults) -> [String: Data] {
        defaults.dictionaryRepresentation().reduce(into: [:]) { result, item in
            if item.key.hasPrefix("sync.baseline."), let value = item.value as? Data { result[item.key] = value }
        }
    }

    func testAttachmentsPublishedBeforeVaultAndRestoredOnSecondDeviceWithoutRemoteGC() async throws {
        let environment = try SyncTestEnvironment()
        let first = try await store(environment, "first", attached: true)
        let second = try await store(environment, "second")
        defer { first.lock(); second.lock() }
        let entry = try XCTUnwrap(first.payload.entries.first)
        let attachment = try XCTUnwrap(entry.attachments.first)
        let bytes = try first.attachmentData(entryID: entry.id, attachmentID: attachment.id)
        let encrypted = try VaultAttachmentDisk.readBlob(attachment.id, vault: first.vaultURL)
        let server = AttachmentSyncServer()
        let syncA = coordinator(environment, server)
        let syncB = coordinator(environment, server)
        await syncA.synchronize(store: first)
        XCTAssertNotNil(syncA.lastSync, syncA.message ?? "")
        let events = await server.events
        XCTAssertEqual(events, ["attachment:\(attachment.id)", "vault"])
        let uploaded = await server.vault
        XCTAssertEqual(uploaded, try first.encryptedSnapshot(), "Never upload a portable backup container as the vault")
        await syncB.synchronize(store: second)
        XCTAssertNotNil(syncB.lastSync, syncB.message ?? "")
        XCTAssertEqual(try second.attachmentData(entryID: entry.id, attachmentID: attachment.id), bytes)
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(attachment.id, vault: second.vaultURL), encrypted)
        XCTAssertEqual(try second.encryptedSnapshot(), uploaded)
        try first.removeAttachment(entryID: entry.id, attachmentID: attachment.id)
        await syncA.synchronize(store: first)
        let retained = await server.object(attachment.id)
        XCTAssertEqual(retained, encrypted, "Unreferenced remote objects must not be garbage collected")
    }

    func testEqualVaultRepairsMissingAttachmentsBothDirectionsWithoutVaultUploadOrBackup() async throws {
        let environment = try SyncTestEnvironment()
        let local = try await store(environment, "local", attached: true)
        defer { local.lock() }
        let entry = try XCTUnwrap(local.payload.entries.first)
        let id = try XCTUnwrap(entry.attachments.first?.id)
        let encrypted = try VaultAttachmentDisk.readBlob(id, vault: local.vaultURL)
        let snapshot = try local.encryptedSnapshot()
        let server = AttachmentSyncServer()
        await server.replaceVault(snapshot)
        let sync = coordinator(environment, server)
        await sync.synchronize(store: local)
        XCTAssertNotNil(sync.lastSync, sync.message ?? "")
        let remoteBlob = await server.object(id)
        XCTAssertEqual(remoteBlob, encrypted)
        try FileManager.default.removeItem(at: blobURL(local, id))
        await sync.synchronize(store: local)
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: local.vaultURL), encrypted)
        XCTAssertEqual(try local.encryptedSnapshot(), snapshot)
        XCTAssertTrue(try BackupFiles.records(vaultURL: local.vaultURL).isEmpty)
        let uploads = await server.events
        XCTAssertEqual(uploads, ["attachment:\(id)"])
    }

    func testMissingRemoteAttachmentPreventsDownloadCommitAndBaseline() async throws {
        let environment = try SyncTestEnvironment()
        let source = try await store(environment, "source", attached: true)
        let target = try await store(environment, "target")
        defer { source.lock(); target.lock() }
        let original = try target.encryptedSnapshot()
        let server = AttachmentSyncServer()
        await server.replaceVault(try source.encryptedSnapshot())
        let sync = coordinator(environment, server)
        await sync.synchronize(store: target)
        XCTAssertEqual(try target.encryptedSnapshot(), original)
        XCTAssertTrue(target.payload.entries.isEmpty)
        XCTAssertNil(sync.lastSync)
        XCTAssertTrue(baselineValues(environment.defaults).isEmpty)
        XCTAssertTrue(sync.message?.contains("attachment") == true && sync.message?.contains("missing") == true, sync.message ?? "")
        XCTAssertTrue(try BackupFiles.records(vaultURL: target.vaultURL).isEmpty)
    }

    func testDownloadRepairsMissingRemoteObjectUsingAuthenticatedLocalBlob() async throws {
        let environment = try SyncTestEnvironment()
        let source = try await store(environment, "source", attached: true)
        let target = try await store(environment, "target")
        defer { source.lock(); target.lock() }
        let server = AttachmentSyncServer()
        let syncA = coordinator(environment, server)
        let syncB = coordinator(environment, server)
        await syncA.synchronize(store: source)
        await syncB.synchronize(store: target)
        var entry = try XCTUnwrap(source.payload.entries.first)
        let id = try XCTUnwrap(entry.attachments.first?.id)
        let blob = try VaultAttachmentDisk.readBlob(id, vault: target.vaultURL)
        entry.name = "remote metadata change"
        try source.save(entry)
        await server.replaceVault(try source.encryptedSnapshot())
        await server.setObject(nil, id: id)
        await syncB.synchronize(store: target)
        XCTAssertEqual(try target.encryptedSnapshot(), try source.encryptedSnapshot())
        let repaired = await server.object(id)
        XCTAssertEqual(repaired, blob)
        XCTAssertNotNil(syncB.lastSync, syncB.message ?? "")
    }

    func testMissingLaterAttachmentDoesNotInstallEarlierStagedAttachment() async throws {
        let environment = try SyncTestEnvironment()
        let source = try await store(environment, "source", attached: true)
        let target = try await store(environment, "target")
        defer { source.lock(); target.lock() }
        let entry = try XCTUnwrap(source.payload.entries.first)
        let file = environment.directory.appendingPathComponent("second.txt")
        try Data("second private attachment".utf8).write(to: file)
        try source.addAttachment(entryID: entry.id, from: file)
        let ids = try XCTUnwrap(source.payload.entries.first).attachments.map(\.id)
            .sorted { $0.uuidString < $1.uuidString }
        XCTAssertEqual(ids.count, 2)
        let server = AttachmentSyncServer()
        await server.replaceVault(try source.encryptedSnapshot())
        await server.setObject(try VaultAttachmentDisk.readBlob(ids[0], vault: source.vaultURL), id: ids[0])
        let original = try target.encryptedSnapshot()
        let sync = coordinator(environment, server)
        await sync.synchronize(store: target)
        XCTAssertEqual(try target.encryptedSnapshot(), original)
        for id in ids { XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(target, id).path)) }
        XCTAssertNil(sync.lastSync)
        XCTAssertTrue(baselineValues(environment.defaults).isEmpty)
        await server.setObject(try VaultAttachmentDisk.readBlob(ids[1], vault: source.vaultURL), id: ids[1])
        await sync.synchronize(store: target)
        XCTAssertEqual(try target.encryptedSnapshot(), try source.encryptedSnapshot())
        for id in ids {
            XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: target.vaultURL),
                           try VaultAttachmentDisk.readBlob(id, vault: source.vaultURL))
        }
    }

    func testTamperedRemoteAttachmentPreventsDownloadCommitAndBaseline() async throws {
        let environment = try SyncTestEnvironment()
        let source = try await store(environment, "source", attached: true)
        let target = try await store(environment, "target")
        defer { source.lock(); target.lock() }
        let original = try target.encryptedSnapshot()
        let id = try XCTUnwrap(source.payload.entries.first?.attachments.first?.id)
        var blob = try VaultAttachmentDisk.readBlob(id, vault: source.vaultURL)
        blob[blob.startIndex] ^= 1
        let server = AttachmentSyncServer()
        await server.replaceVault(try source.encryptedSnapshot())
        await server.setObject(blob, id: id)
        let sync = coordinator(environment, server)
        await sync.synchronize(store: target)
        XCTAssertEqual(try target.encryptedSnapshot(), original)
        XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(target, id).path))
        XCTAssertNil(sync.lastSync)
        XCTAssertTrue(baselineValues(environment.defaults).isEmpty)
        XCTAssertTrue(try BackupFiles.records(vaultURL: target.vaultURL).isEmpty)
    }

    func testEqualVaultMissingBothCopiesDoesNotAdvanceExistingBaseline() async throws {
        let environment = try SyncTestEnvironment()
        let local = try await store(environment, "local", attached: true)
        defer { local.lock() }
        let id = try XCTUnwrap(local.payload.entries.first?.attachments.first?.id)
        let server = AttachmentSyncServer()
        let sync = coordinator(environment, server)
        await sync.synchronize(store: local)
        let before = baselineValues(environment.defaults)
        XCTAssertFalse(before.isEmpty)
        let date = sync.lastSync
        await server.setObject(nil, id: id)
        try FileManager.default.removeItem(at: blobURL(local, id))
        await sync.synchronize(store: local)
        XCTAssertEqual(sync.lastSync, date)
        XCTAssertEqual(baselineValues(environment.defaults), before)
        XCTAssertTrue(sync.message?.contains("attachment") == true && sync.message?.contains("missing") == true)
    }

    func testLocalCorruptionAndRemoteCiphertextCollisionNeverPublishVault() async throws {
        for corruptLocal in [false, true] {
            let environment = try SyncTestEnvironment()
            let local = try await store(environment, "local", attached: true)
            defer { local.lock() }
            let id = try XCTUnwrap(local.payload.entries.first?.attachments.first?.id)
            var corrupt = try VaultAttachmentDisk.readBlob(id, vault: local.vaultURL)
            corrupt[corrupt.startIndex] ^= 1
            let server = AttachmentSyncServer()
            if corruptLocal { try corrupt.write(to: blobURL(local, id)) }
            else { await server.setObject(corrupt, id: id) }
            let sync = coordinator(environment, server)
            await sync.synchronize(store: local)
            let uploaded = await server.vault
            XCTAssertNil(uploaded)
            XCTAssertNil(sync.lastSync)
            XCTAssertTrue(baselineValues(environment.defaults).isEmpty)
        }
    }

    func testEqualVaultRejectsDifferentCiphertextWithoutAdvancingBaseline() async throws {
        let environment = try SyncTestEnvironment()
        let local = try await store(environment, "local", attached: true)
        defer { local.lock() }
        let id = try XCTUnwrap(local.payload.entries.first?.attachments.first?.id)
        let good = try VaultAttachmentDisk.readBlob(id, vault: local.vaultURL)
        var different = good
        different[different.startIndex] ^= 1
        let server = AttachmentSyncServer()
        await server.replaceVault(try local.encryptedSnapshot())
        await server.setObject(different, id: id)
        let sync = coordinator(environment, server)
        await sync.synchronize(store: local)
        XCTAssertNil(sync.lastSync)
        XCTAssertTrue(sync.message?.contains("ciphertext collision") == true)
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: local.vaultURL), good)
        XCTAssertTrue(baselineValues(environment.defaults).isEmpty)
    }

    func testAttachmentCreateRaceAcceptsOnlyIdenticalCiphertext() async throws {
        for identical in [true, false] {
            let environment = try SyncTestEnvironment()
            let local = try await store(environment, "local", attached: true)
            defer { local.lock() }
            let server = AttachmentSyncServer()
            await server.raceNextCreate(identical: identical)
            let sync = coordinator(environment, server)
            await sync.synchronize(store: local)
            let uploaded = await server.vault
            if identical {
                XCTAssertEqual(uploaded, try local.encryptedSnapshot())
                XCTAssertNotNil(sync.lastSync, sync.message ?? "")
            } else {
                XCTAssertNil(uploaded)
                XCTAssertNil(sync.lastSync)
                XCTAssertTrue(sync.message?.contains("ciphertext collision") == true)
            }
        }
    }

    func testKeepLocalPreservesCompleteRemoteBackupBeforePublishingLocalAttachments() async throws {
        let environment = try SyncTestEnvironment()
        let local = try await store(environment, "local", attached: true)
        let remote = try await store(environment, "remote", attached: true)
        defer { local.lock(); remote.lock() }
        let id = try XCTUnwrap(remote.payload.entries.first?.attachments.first?.id)
        let remoteVault = try remote.encryptedSnapshot()
        let remoteBlob = try VaultAttachmentDisk.readBlob(id, vault: remote.vaultURL)
        let localVault = try local.encryptedSnapshot()
        let server = AttachmentSyncServer()
        await server.replaceVault(remoteVault)
        await server.setObject(remoteBlob, id: id)
        let sync = coordinator(environment, server)
        await sync.synchronize(store: local)
        XCTAssertTrue(sync.hasConflict)
        await sync.resolve(useRemote: false, store: local)
        XCTAssertFalse(sync.hasConflict)
        XCTAssertNotNil(sync.lastSync, sync.message ?? "")
        let records = try BackupFiles.records(vaultURL: local.vaultURL)
        let record = try XCTUnwrap(records.first)
        let backup = try VaultBackup.decode(BackupFiles.read(record.url, maximumBytes: VaultBackup.maximumBytes))
        XCTAssertEqual(backup.vault, remoteVault)
        XCTAssertEqual(backup.attachments, [id: remoteBlob])
        let uploaded = await server.vault
        XCTAssertEqual(uploaded, localVault)
        XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(local, id).path), "Remote backup must not install remote-only blobs")
        let retained = await server.object(id)
        XCTAssertEqual(retained, remoteBlob)
    }

    func testKeepRemoteRestoresAttachmentsAndPreservesCompleteLocalBackup() async throws {
        let environment = try SyncTestEnvironment()
        let local = try await store(environment, "local", attached: true)
        let remote = try await store(environment, "remote", attached: true)
        defer { local.lock(); remote.lock() }
        let localID = try XCTUnwrap(local.payload.entries.first?.attachments.first?.id)
        let localVault = try local.encryptedSnapshot()
        let localBlob = try VaultAttachmentDisk.readBlob(localID, vault: local.vaultURL)
        let remoteID = try XCTUnwrap(remote.payload.entries.first?.attachments.first?.id)
        let remoteBlob = try VaultAttachmentDisk.readBlob(remoteID, vault: remote.vaultURL)
        let server = AttachmentSyncServer()
        await server.replaceVault(try remote.encryptedSnapshot())
        await server.setObject(remoteBlob, id: remoteID)
        let sync = coordinator(environment, server)
        await sync.synchronize(store: local)
        XCTAssertTrue(sync.hasConflict)
        await sync.resolve(useRemote: true, store: local)
        XCTAssertNotNil(sync.lastSync, sync.message ?? "")
        XCTAssertEqual(try local.encryptedSnapshot(), try remote.encryptedSnapshot())
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(remoteID, vault: local.vaultURL), remoteBlob)
        let records = try BackupFiles.records(vaultURL: local.vaultURL)
        let backup = try VaultBackup.decode(BackupFiles.read(XCTUnwrap(records.first).url, maximumBytes: VaultBackup.maximumBytes))
        XCTAssertEqual(backup.vault, localVault)
        XCTAssertEqual(backup.attachments, [localID: localBlob])
    }

    func testRemoteVaultChangedDuringAttachmentDownloadDoesNotCommit() async throws {
        let environment = try SyncTestEnvironment()
        let source = try await store(environment, "source", attached: true)
        let target = try await store(environment, "target")
        defer { source.lock(); target.lock() }
        let original = try target.encryptedSnapshot()
        let id = try XCTUnwrap(source.payload.entries.first?.attachments.first?.id)
        let server = AttachmentSyncServer()
        await server.replaceVault(try source.encryptedSnapshot())
        await server.setObject(try VaultAttachmentDisk.readBlob(id, vault: source.vaultURL), id: id)
        await server.changeRevisionOnNextAttachmentDownload()
        let sync = coordinator(environment, server)
        await sync.synchronize(store: target)
        XCTAssertEqual(try target.encryptedSnapshot(), original)
        XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(target, id).path))
        XCTAssertNil(sync.lastSync)
        XCTAssertTrue(sync.message?.contains("remote version changed again") == true)
    }

    func testLockCancelAndConfigurationSwitchDuringAttachmentIOPreventVaultPublication() async throws {
        for mode in 0..<4 {
            let environment = try SyncTestEnvironment()
            let local = try await store(environment, "local", attached: true)
            defer { local.lock() }
            let server = AttachmentSyncServer()
            let sync = coordinator(environment, server)
            sync.configuration.password = "webdav-secret"
            sync.s3Configuration.secretAccessKey = "s3-secret"
            await server.interceptNextAttachmentDownload {
                switch mode {
                case 0: local.lock()
                case 1: local.lock(); sync.cancelPending()
                case 2: sync.backend = .s3
                default: sync.configuration.serverURL = "https://other.invalid/"
                }
            }
            await sync.synchronize(store: local)
            let uploaded = await server.vault
            let cancelled = await server.observedCancellation
            XCTAssertNil(uploaded)
            XCTAssertNil(sync.lastSync)
            XCTAssertFalse(sync.busy)
            XCTAssertTrue(baselineValues(environment.defaults).isEmpty)
            if mode != 0 { XCTAssertTrue(cancelled, "The actual client task must be cancelled") }
            if mode == 1 {
                XCTAssertEqual(sync.configuration.password, "")
                XCTAssertEqual(sync.s3Configuration.secretAccessKey, "")
                XCTAssertNil(sync.message)
                XCTAssertFalse(sync.hasConflict)
            }
        }
    }

    func testLocalEditDuringAttachmentIOStopsPublication() async throws {
        let environment = try SyncTestEnvironment()
        let local = try await store(environment, "local", attached: true)
        defer { local.lock() }
        let server = AttachmentSyncServer()
        let sync = coordinator(environment, server)
        await server.interceptNextAttachmentDownload {
            do { try local.save(VaultEntry(name: "edited while waiting")) }
            catch { XCTFail(error.localizedDescription) }
        }
        await sync.synchronize(store: local)
        let uploaded = await server.vault
        XCTAssertNil(uploaded)
        XCTAssertNil(sync.lastSync)
        XCTAssertTrue(sync.message?.contains("changed") == true)
    }

    func testS3ConflictResolutionUsesS3FactoryAndCancelClearsPendingChoice() async throws {
        let environment = try SyncTestEnvironment()
        let local = try await store(environment, "local", attached: true)
        let remote = try await store(environment, "remote", attached: true)
        defer { local.lock(); remote.lock() }
        let server = AttachmentSyncServer()
        await server.replaceVault(try remote.encryptedSnapshot())
        let id = try XCTUnwrap(remote.payload.entries.first?.attachments.first?.id)
        await server.setObject(try VaultAttachmentDisk.readBlob(id, vault: remote.vaultURL), id: id)
        var factories = 0
        let sync = SyncCoordinator(defaults: environment.defaults, makeClient: { _ in
            XCTFail("S3 conflict resolution must not construct WebDAV")
            return server
        }, makeS3Client: { _ in
            factories += 1
            return server
        })
        sync.backend = .s3
        sync.s3Configuration = S3Configuration(endpoint: "https://account.r2.cloudflarestorage.com", bucket: "test-bucket",
            accessKeyID: "TESTACCESSID001", secretAccessKey: "secret", prefix: "vault")
        await sync.synchronize(store: local)
        XCTAssertTrue(sync.hasConflict, sync.message ?? "Missing conflict")
        sync.cancelPending()
        XCTAssertFalse(sync.hasConflict)
        await sync.resolve(useRemote: true, store: local)
        XCTAssertEqual(factories, 1, "A cancelled conflict must not be resolvable")
        sync.s3Configuration.secretAccessKey = "secret"
        await sync.synchronize(store: local)
        XCTAssertTrue(sync.hasConflict, sync.message ?? "Missing conflict")
        await sync.resolve(useRemote: true, store: local)
        XCTAssertEqual(factories, 3)
        XCTAssertFalse(sync.hasConflict)
        XCTAssertNotNil(sync.lastSync, sync.message ?? "")
        XCTAssertEqual(try local.encryptedSnapshot(), try remote.encryptedSnapshot())
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: local.vaultURL),
                       try VaultAttachmentDisk.readBlob(id, vault: remote.vaultURL))
    }

    func testS3FactorySelectionIndependentBaselinesAndNonsecretDefaults() async throws {
        let environment = try SyncTestEnvironment()
        let local = try await store(environment, "local", attached: true)
        defer { local.lock() }
        let dav = AttachmentSyncServer()
        let s3 = AttachmentSyncServer()
        var davFactories = 0
        var s3Factories = 0
        let sync = SyncCoordinator(defaults: environment.defaults, makeClient: { _ in
            davFactories += 1
            return dav
        }, makeS3Client: { config in
            XCTAssertEqual(config.region, "auto")
            s3Factories += 1
            return s3
        })
        sync.configuration = WebDAVConfiguration(serverURL: "https://sync.invalid/existing/", password: "dav-secret-value")
        sync.s3Configuration = S3Configuration(endpoint: "https://account.r2.cloudflarestorage.com", bucket: "test-bucket",
            accessKeyID: "TESTACCESSIDVALUE001", secretAccessKey: "s3-secret-value", prefix: "vault")
        await sync.synchronize(store: local)
        XCTAssertEqual(davFactories, 1)
        XCTAssertEqual(s3Factories, 0)
        let davBaseline = baselineValues(environment.defaults)
        sync.backend = .s3
        XCTAssertNil(sync.lastSync)
        try sync.saveConfiguration(persistCredentials: false)
        XCTAssertEqual(environment.defaults.string(forKey: "sync.backend"), "s3")
        await sync.testConnection()
        await sync.synchronize(store: local)
        XCTAssertEqual(davFactories, 1)
        XCTAssertEqual(s3Factories, 2)
        XCTAssertNotNil(sync.lastSync, sync.message ?? "")
        let both = baselineValues(environment.defaults)
        XCTAssertEqual(both.count, 2)
        for (key, value) in davBaseline { XCTAssertEqual(both[key], value) }
        let id = try XCTUnwrap(local.payload.entries.first?.attachments.first?.id)
        let uploaded = await s3.object(id)
        XCTAssertEqual(uploaded, try VaultAttachmentDisk.readBlob(id, vault: local.vaultURL))
        sync.s3Configuration.secretAccessKey = "rotated-secret-value"
        sync.s3Configuration.accessKeyID = "ROTATEDACCESSID002"
        XCTAssertNotNil(sync.lastSync, "Credentials must not partition the S3 baseline")
        for change in 0..<3 {
            let original = sync.s3Configuration
            switch change {
            case 0: sync.s3Configuration.endpoint = "https://other.r2.cloudflarestorage.com"
            case 1: sync.s3Configuration.bucket = "other-bucket"
            default: sync.s3Configuration.prefix = "other-prefix"
            }
            XCTAssertNil(sync.lastSync)
            sync.s3Configuration = original
            XCTAssertNotNil(sync.lastSync)
        }
        sync.backend = .webDAV
        XCTAssertNotNil(sync.lastSync, "Legacy WebDAV baseline key remains readable")
        let serializedDefaults = String(describing: environment.defaults.dictionaryRepresentation())
        for secret in ["dav-secret-value", "s3-secret-value", "TESTACCESSIDVALUE001", "rotated-secret-value", "ROTATEDACCESSID002"] {
            XCTAssertFalse(serializedDefaults.contains(secret))
        }
    }
}

private final class SyncTestEnvironment {
    let directory: URL
    let defaults: UserDefaults
    private let suite: String

    init() throws {
        suite = "SyncAttachmentTests-" + UUID().uuidString
        defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.set(true, forKey: "allowMobileEditing")
        directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent(suite, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    deinit {
        defaults.removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: directory)
    }
}

private actor AttachmentSyncServer: WebDAVServing {
    private(set) var vault: Data?
    private var revision = 0
    private var objects: [UUID: Data] = [:]
    private(set) var events: [String] = []
    private var createRace: Bool?
    private var changeRevision = false
    private var attachmentAction: (@MainActor () -> Void)?
    private(set) var observedCancellation = false
    private var etag: String { "\"revision-\(revision)\"" }

    func testConnection() async throws { }
    func download() async throws -> WebDAVDownload? {
        vault.map { WebDAVDownload(data: $0, etag: etag) }
    }
    func upload(_ data: Data, expectedETag: String?, createOnly: Bool) async throws -> String? {
        try Task.checkCancellation()
        if createOnly {
            guard vault == nil, expectedETag == nil else { throw WebDAVError.preconditionFailed }
        } else {
            guard vault != nil, expectedETag == etag else { throw WebDAVError.preconditionFailed }
        }
        vault = data
        revision += 1
        events.append("vault")
        return etag
    }
    func downloadAttachment(id: UUID) async throws -> WebDAVDownload? {
        let action = attachmentAction
        attachmentAction = nil
        if let action { await action() }
        observedCancellation = Task.isCancelled
        if changeRevision { revision += 1; changeRevision = false }
        // Deliberately return late results even after cancellation to exercise coordinator checks.
        return objects[id].map { WebDAVDownload(data: $0, etag: "\"object\"") }
    }
    func uploadAttachment(_ data: Data, id: UUID) async throws -> String? {
        try Task.checkCancellation()
        if let identical = createRace {
            createRace = nil
            var competing = data
            if !identical { competing[competing.startIndex] ^= 1 }
            objects[id] = competing
            throw WebDAVError.preconditionFailed
        }
        guard objects[id] == nil else { throw WebDAVError.preconditionFailed }
        objects[id] = data
        events.append("attachment:\(id)")
        return "\"object\""
    }
    func replaceVault(_ data: Data) { vault = data; revision += 1 }
    func setObject(_ data: Data?, id: UUID) { objects[id] = data }
    func object(_ id: UUID) -> Data? { objects[id] }
    func raceNextCreate(identical: Bool) { createRace = identical }
    func changeRevisionOnNextAttachmentDownload() { changeRevision = true }
    func interceptNextAttachmentDownload(_ action: @escaping @MainActor () -> Void) { attachmentAction = action }
}

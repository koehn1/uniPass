import Foundation
import XCTest
@testable import uniPass

@MainActor
final class VaultSyncTests: XCTestCase {
    private let password = "prepared-sync-test-password"

    private struct Remote {
        var payload: VaultPayload
        var vault: Data
        var blobs: [UUID: Data]
        var plaintext: Data
        var ids: [UUID] { payload.entries.flatMap { $0.attachments.map(\.id) } }
    }

    private func context() throws -> (URL, UserDefaults) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let suite = "VaultSyncTests.\(UUID().uuidString)"
        let preferences = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock {
            try? FileManager.default.removeItem(at: root)
            UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
        }
        return (root, preferences)
    }

    private func remote(count: Int = 1, password: String? = nil) throws -> Remote {
        let plaintext = Data("private attachment plaintext \(UUID().uuidString)".utf8)
        var entry = VaultEntry(name: "private title", password: "private entry password")
        var blobs: [UUID: Data] = [:]
        for index in 0..<count {
            let attachment = VaultAttachment(fileName: "private-\(index).txt", byteCount: Int64(plaintext.count),
                key: try VaultCrypto.randomBytes(count: 32))
            entry.attachments.append(attachment)
            blobs[attachment.id] = try VaultCrypto.sealAttachment(plaintext, entryID: entry.id, attachment: attachment)
        }
        let payload = VaultPayload(entries: [entry])
        return Remote(payload: payload,
            vault: try VaultCrypto.prepare(payload, password: VaultCrypto.passwordData(password ?? self.password)).data,
            blobs: blobs, plaintext: plaintext)
    }

    private func store(_ remote: Remote, at url: URL, preferences: UserDefaults,
                       installBlobs: Bool = true) async throws -> VaultStore {
        try VaultDisk.write(remote.vault, to: url, creating: true, expected: nil)
        if installBlobs {
            for (id, blob) in remote.blobs { try VaultAttachmentDisk.writeBlob(blob, id: id, vault: url) }
        }
        let store = VaultStore(vaultURL: url, preferences: preferences)
        try await store.unlock(password: password)
        return store
    }

    private func stage(_ remote: Remote, in store: VaultStore, version: VaultSyncVersion) throws {
        for (id, blob) in remote.blobs { try store.stageSyncAttachment(blob, id: id, version: version) }
    }

    private func blobURL(_ id: UUID, store: VaultStore) -> URL {
        store.vaultURL.deletingLastPathComponent().appendingPathComponent("documents")
            .appendingPathComponent(VaultAttachmentDisk.blobName(id))
    }

    func testPrepareRejectsWrongPasswordAndLockedSession() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let wrong = try remote(password: "different master password")
        do {
            _ = try await store.prepareSyncVersion(wrong.vault)
            XCTFail("Wrong-password preparation succeeded")
        } catch VaultError.invalidPasswordOrCorruptVault { }
        store.lock()
        do {
            _ = try await store.prepareSyncVersion(local.vault)
            XCTFail("Locked preparation succeeded")
        } catch VaultError.locked { }
    }

    func testPendingPreparationCannotSurviveLockOrLocationSwitch() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let incoming = try remote() // different salt requires PBKDF2
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        var started = false
        let pending = Task {
            started = true
            return try await store.prepareSyncVersion(incoming.vault)
        }
        while !started { await Task.yield() }
        store.lock()
        try await store.unlock(password: password)
        do {
            let version = try await pending.value
            defer { store.discardSyncVersion(version) }
            XCTAssertThrowsError(try store.validateSyncVersion(version))
        } catch VaultError.operationCancelled { }

        let other = root.appendingPathComponent("other", isDirectory: true)
        try VaultDisk.write(local.vault, to: other.appendingPathComponent("vault.unipass"), creating: true, expected: nil)
        var switchingStarted = false
        let switching = Task {
            switchingStarted = true
            return try await store.prepareSyncVersion(incoming.vault)
        }
        while !switchingStarted { await Task.yield() }
        try store.openDirectory(other)
        try await store.unlock(password: password)
        do {
            let version = try await switching.value
            defer { store.discardSyncVersion(version) }
            XCTAssertThrowsError(try store.commitSyncVersion(version))
        } catch VaultError.operationCancelled { }
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), local.vault)
    }

    func testBindingRejectsReopenPermissionsEditsOtherStoreAndDiscard() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let url = root.appendingPathComponent("vault.unipass")
        let store = try await store(local, at: url, preferences: preferences)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(local.vault)
        defer { store.discardSyncVersion(version) }
        let other = VaultStore(vaultURL: url, preferences: preferences)
        try await other.unlock(password: password)
        defer { other.lock() }
        XCTAssertThrowsError(try other.validateSyncVersion(version))
        store.lock()
        try await store.unlock(password: password)
        XCTAssertThrowsError(try store.validateSyncVersion(version))
        let permissionVersion = try await store.prepareSyncVersion(local.vault)
        defer { store.discardSyncVersion(permissionVersion) }
        store.allowMobileEditing.toggle()
        XCTAssertThrowsError(try store.validateSyncVersion(permissionVersion))
        store.allowMobileEditing = true
        let editVersion = try await store.prepareSyncVersion(local.vault)
        defer { store.discardSyncVersion(editVersion) }
        try store.save(VaultEntry(name: "local edit"))
        XCTAssertThrowsError(try store.validateSyncVersion(editVersion))
        let discarded = try await store.prepareSyncVersion(store.encryptedSnapshot())
        store.lock()
        store.discardSyncVersion(discarded)
        store.discardSyncVersion(discarded)
        XCTAssertThrowsError(try store.validateSyncVersion(discarded))
    }

    func testStagingReturnsOnlyAuthenticatedCiphertextAndPortableRemoteBackup() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let incoming = try remote(count: 2)
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        XCTAssertEqual(Set(version.attachmentIDs), Set(incoming.ids))
        XCTAssertEqual(version.encryptedVault, incoming.vault)
        XCTAssertNil(version.expectedAttachmentBytes(id: UUID()))
        try stage(incoming, in: store, version: version)
        for id in incoming.ids {
            let cipher = try XCTUnwrap(store.syncAttachmentData(id: id, version: version))
            XCTAssertEqual(cipher, incoming.blobs[id])
            XCTAssertEqual(version.expectedAttachmentBytes(id: id), cipher.count)
            XCTAssertNil(cipher.range(of: incoming.plaintext))
            XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(id, store: store).path))
        }
        let url = try store.preserveSyncVersion(version)
        let bytes = try Data(contentsOf: url)
        XCTAssertNil(bytes.range(of: incoming.plaintext))
        let backup = try VaultBackup.decode(bytes)
        XCTAssertEqual(backup.vault, incoming.vault)
        XCTAssertEqual(backup.attachments, incoming.blobs)
        try VaultBackup.authenticate(backup, payload: incoming.payload)
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), local.vault)
    }

    func testMissingIsNilButCorruptionAndSymlinksThrow() async throws {
        let (root, preferences) = try context()
        let incoming = try remote()
        let store = try await store(incoming, at: root.appendingPathComponent("vault.unipass"),
            preferences: preferences, installBlobs: false)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        let id = incoming.ids[0]
        // No documents directory at all is genuine absence.
        XCTAssertNil(try store.syncAttachmentData(id: id, version: version))
        let documents = blobURL(id, store: store).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
        XCTAssertNil(try store.syncAttachmentData(id: id, version: version))
        var corrupt = try XCTUnwrap(incoming.blobs[id])
        corrupt[corrupt.startIndex] ^= 1
        try corrupt.write(to: blobURL(id, store: store))
        XCTAssertThrowsError(try store.syncAttachmentData(id: id, version: version))
        try FileManager.default.removeItem(at: blobURL(id, store: store))
        try FileManager.default.createSymbolicLink(atPath: blobURL(id, store: store).path,
            withDestinationPath: root.appendingPathComponent("nonexistent").path)
        XCTAssertThrowsError(try store.syncAttachmentData(id: id, version: version))
        try FileManager.default.removeItem(at: documents)
        try FileManager.default.createSymbolicLink(atPath: documents.path, withDestinationPath: root.path)
        XCTAssertThrowsError(try store.syncAttachmentData(id: id, version: version))
    }

    func testStageRejectsUnknownWrongSizePlaintextAndBadAuthentication() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let incoming = try remote()
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        let id = incoming.ids[0]
        let cipher = try XCTUnwrap(incoming.blobs[id])
        XCTAssertThrowsError(try store.stageSyncAttachment(cipher, id: UUID(), version: version))
        XCTAssertThrowsError(try store.stageSyncAttachment(Data(cipher.dropLast()), id: id, version: version))
        XCTAssertThrowsError(try store.stageSyncAttachment(incoming.plaintext, id: id, version: version))
        var corrupt = cipher
        corrupt[corrupt.startIndex] ^= 1
        XCTAssertThrowsError(try store.stageSyncAttachment(corrupt, id: id, version: version))
        XCTAssertNil(try store.syncAttachmentData(id: id, version: version))
        try store.stageSyncAttachment(cipher, id: id, version: version)
        try store.stageSyncAttachment(cipher, id: id, version: version) // retry is idempotent
    }

    func testCommitPreflightsAllAttachmentsBeforeAnyInstallation() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let incoming = try remote(count: 2)
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        let first = incoming.ids[0]
        try store.stageSyncAttachment(try XCTUnwrap(incoming.blobs[first]), id: first, version: version)
        XCTAssertThrowsError(try store.commitSyncVersion(version))
        XCTAssertThrowsError(try store.preserveSyncVersion(version))
        for id in incoming.ids { XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(id, store: store).path)) }
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), local.vault)
        let published = (try? FileManager.default.contentsOfDirectory(at: store.backupDirectory,
            includingPropertiesForKeys: nil)) ?? []
        XCTAssertTrue(published.isEmpty)
    }

    func testCommitPersistsExactRemoteBytesAndCompleteOldBackupInReadOnlyMode() async throws {
        let (root, preferences) = try context()
        let local = try remote()
        let incoming = try remote(count: 2)
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        XCTAssertFalse(store.allowMobileEditing)
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        try stage(incoming, in: store, version: version)
        try store.commitSyncVersion(version)
        XCTAssertEqual(try store.encryptedSnapshot(), incoming.vault)
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), incoming.vault)
        XCTAssertEqual(store.payload.entries, incoming.payload.entries)
        for id in incoming.ids {
            XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: store.vaultURL), incoming.blobs[id])
        }
        let backups = try FileManager.default.contentsOfDirectory(at: store.backupDirectory, includingPropertiesForKeys: nil)
        XCTAssertEqual(backups.count, 1)
        let backup = try VaultBackup.decode(Data(contentsOf: XCTUnwrap(backups.first)))
        XCTAssertEqual(backup.vault, local.vault)
        XCTAssertEqual(backup.attachments, local.blobs)
        try VaultBackup.authenticate(backup, payload: local.payload)
    }

    func testMissingOldAttachmentPreventsReplacementWithoutPartialWrites() async throws {
        let (root, preferences) = try context()
        let local = try remote()
        let incoming = try remote()
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"),
            preferences: preferences, installBlobs: false)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        try stage(incoming, in: store, version: version)
        XCTAssertThrowsError(try store.commitSyncVersion(version))
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), local.vault)
        XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(incoming.ids[0], store: store).path))
    }

    func testSameVaultRepairsMissingAttachmentsWithoutOldBackup() async throws {
        let (root, preferences) = try context()
        let incoming = try remote(count: 2)
        let store = try await store(incoming, at: root.appendingPathComponent("vault.unipass"),
            preferences: preferences, installBlobs: false)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        try stage(incoming, in: store, version: version)
        try store.commitSyncVersion(version)
        try store.commitSyncVersion(version)
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), incoming.vault)
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.backupDirectory.path))
        for id in incoming.ids {
            XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: store.vaultURL), incoming.blobs[id])
        }
    }

    func testCancelledTasksCannotPrepareOrCommitAndDoNotConsumeVersion() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let incoming = try remote()
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let cancelledPreparation = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await store.prepareSyncVersion(incoming.vault)
        }
        do {
            let version = try await cancelledPreparation.value
            store.discardSyncVersion(version)
            XCTFail("Cancelled preparation returned a usable version")
        } catch VaultError.operationCancelled { }

        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        try stage(incoming, in: store, version: version)
        let cancelledCommit = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try store.commitSyncVersion(version)
        }
        do {
            try await cancelledCommit.value
            XCTFail("Cancelled commit succeeded")
        } catch VaultError.operationCancelled { }
        XCTAssertEqual(try store.encryptedSnapshot(), local.vault)
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.backupDirectory.path))
        for id in incoming.ids { XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(id, store: store).path)) }
        // Cancelling one caller does not revoke a still-current version owned by another caller.
        try store.validateSyncVersion(version)
        try store.commitSyncVersion(version)
        XCTAssertEqual(try store.encryptedSnapshot(), incoming.vault)
        XCTAssertThrowsError(try store.validateSyncVersion(version))
    }

    func testExternalReplacementRejectsPreparedVersionWithoutInstallingAttachments() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let incoming = try remote()
        let external = try remote(count: 0)
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        try stage(incoming, in: store, version: version)
        try VaultDisk.write(external.vault, to: store.vaultURL, creating: false, expected: local.vault)
        XCTAssertThrowsError(try store.validateSyncVersion(version)) { error in
            guard case VaultError.externalChange = error else { return XCTFail("Unexpected error: \(error)") }
        }
        XCTAssertThrowsError(try store.commitSyncVersion(version))
        XCTAssertThrowsError(try store.preserveSyncVersion(version))
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), external.vault)
        XCTAssertEqual(try store.encryptedSnapshot(), local.vault)
        for id in incoming.ids { XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(id, store: store).path)) }
    }

    func testBackupPublicationFailurePreventsAllAttachmentInstallation() async throws {
        let (root, preferences) = try context()
        let local = try remote()
        let incoming = try remote(count: 2)
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        try stage(incoming, in: store, version: version)
        let obstruction = Data("not a backup directory".utf8)
        try obstruction.write(to: store.backupDirectory)
        XCTAssertThrowsError(try store.commitSyncVersion(version))
        XCTAssertEqual(try Data(contentsOf: store.backupDirectory), obstruction)
        XCTAssertEqual(try store.encryptedSnapshot(), local.vault)
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), local.vault)
        XCTAssertEqual(store.payload.entries, local.payload.entries)
        for id in incoming.ids { XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(id, store: store).path)) }
        for id in local.ids {
            XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: store.vaultURL), local.blobs[id])
        }
    }

    func testVaultRenameFailureRollsBackOnlyNewBlobsAndAllowsRetry() async throws {
        let (root, preferences) = try context()
        let local = try remote()
        var incoming = try remote(count: 2)
        incoming.payload.entries += local.payload.entries
        incoming.blobs.merge(local.blobs) { first, _ in first }
        incoming.vault = try VaultCrypto.prepare(incoming.payload, password: VaultCrypto.passwordData(password)).data
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        try stage(incoming, in: store, version: version)
        // An immutable destination remains readable for preflight/backup, but its
        // final atomic rename fails after the missing attachments have been written.
        try FileManager.default.setAttributes([.immutable: true], ofItemAtPath: store.vaultURL.path)
        defer { try? FileManager.default.setAttributes([.immutable: false], ofItemAtPath: store.vaultURL.path) }
        XCTAssertThrowsError(try store.commitSyncVersion(version)) { error in
            XCTAssertEqual((error as? POSIXError)?.code, .EPERM)
        }
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), local.vault)
        XCTAssertEqual(try store.encryptedSnapshot(), local.vault)
        XCTAssertEqual(store.payload.entries, local.payload.entries)
        for id in incoming.ids where local.blobs[id] == nil {
            XCTAssertFalse(FileManager.default.fileExists(atPath: blobURL(id, store: store).path))
        }
        for id in local.ids {
            XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: store.vaultURL), local.blobs[id])
        }
        let backups = try FileManager.default.contentsOfDirectory(at: store.backupDirectory, includingPropertiesForKeys: nil)
        XCTAssertEqual(backups.count, 1, "The complete old backup must precede the failed vault rename")
        let backup = try VaultBackup.decode(Data(contentsOf: XCTUnwrap(backups.first)))
        XCTAssertEqual(backup.vault, local.vault)
        XCTAssertEqual(backup.attachments, local.blobs)
        try VaultBackup.authenticate(backup, payload: local.payload)
        try FileManager.default.setAttributes([.immutable: false], ofItemAtPath: store.vaultURL.path)
        try store.commitSyncVersion(version)
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), incoming.vault)
        for id in incoming.ids {
            XCTAssertEqual(try VaultAttachmentDisk.readBlob(id, vault: store.vaultURL), incoming.blobs[id])
        }
    }

    func testStageRejectsAuthenticatedCiphertextFromAnotherAttachment() async throws {
        let (root, preferences) = try context()
        let incoming = try remote(count: 2)
        let store = try await store(incoming, at: root.appendingPathComponent("vault.unipass"),
            preferences: preferences, installBlobs: false)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        let first = incoming.ids[0]
        let second = incoming.ids[1]
        let validForOtherID = try XCTUnwrap(incoming.blobs[second])
        XCTAssertEqual(version.expectedAttachmentBytes(id: first), validForOtherID.count)
        XCTAssertThrowsError(try store.stageSyncAttachment(validForOtherID, id: first, version: version))
        XCTAssertNil(try store.syncAttachmentData(id: first, version: version))
    }

    func testLargeAggregatePreparesButBackupRejectsBeforeReadingBlobs() async throws {
        let (root, preferences) = try context()
        let local = try remote(count: 0)
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let attachments = try (0..<17).map { index in
            VaultAttachment(fileName: "large-\(index)", byteCount: Int64(VaultCrypto.maximumAttachmentBytes),
                key: try VaultCrypto.randomBytes(count: 32))
        }
        let payload = VaultPayload(entries: [VaultEntry(attachments: attachments)])
        let vault = try VaultCrypto.prepare(payload, password: VaultCrypto.passwordData(password)).data
        let version = try await store.prepareSyncVersion(vault)
        defer { store.discardSyncVersion(version) }
        XCTAssertEqual(version.attachmentIDs.count, 17)
        XCTAssertEqual(version.expectedAttachmentBytes(id: attachments[0].id), VaultCrypto.maximumAttachmentBytes + 28)
        XCTAssertNil(try store.syncAttachmentData(id: attachments[0].id, version: version))
        XCTAssertThrowsError(try store.preserveSyncVersion(version)) { error in
            guard case VaultError.dataTooLarge = error else { return XCTFail("Unexpected error: \(error)") }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.backupDirectory.path))
    }

    func testSameUUIDDifferentCipherCanBePreservedButNeverOverwriteLocal() async throws {
        let (root, preferences) = try context()
        let local = try remote()
        var incoming = local
        let entry = try XCTUnwrap(local.payload.entries.first)
        let attachment = try XCTUnwrap(entry.attachments.first)
        incoming.blobs[attachment.id] = try VaultCrypto.sealAttachment(local.plaintext, entryID: entry.id, attachment: attachment)
        incoming.vault = try VaultCrypto.prepare(local.payload, password: VaultCrypto.passwordData(password)).data
        XCTAssertNotEqual(incoming.blobs[attachment.id], local.blobs[attachment.id])
        let store = try await store(local, at: root.appendingPathComponent("vault.unipass"), preferences: preferences)
        defer { store.lock() }
        let version = try await store.prepareSyncVersion(incoming.vault)
        defer { store.discardSyncVersion(version) }
        try stage(incoming, in: store, version: version)
        let preserved = try store.preserveSyncVersion(version)
        XCTAssertEqual(try VaultBackup.decode(Data(contentsOf: preserved)).attachments, incoming.blobs)
        XCTAssertThrowsError(try store.commitSyncVersion(version))
        XCTAssertEqual(try Data(contentsOf: store.vaultURL), local.vault)
        XCTAssertEqual(try VaultAttachmentDisk.readBlob(attachment.id, vault: store.vaultURL), local.blobs[attachment.id])
    }
}

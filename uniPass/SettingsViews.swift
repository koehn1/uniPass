import SwiftUI
import UniformTypeIdentifiers
import Foundation

struct EncryptedBackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    static var writableContentTypes: [UTType] { [.data] }
    var data: Data

    init(data: Data = Data()) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        guard let contents = configuration.file.regularFileContents,
              contents.count <= VaultBackup.maximumBytes else {
            throw VaultError.dataTooLarge
        }
        data = contents
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

@MainActor
struct SettingsView: View {
    @EnvironmentObject var store: VaultStore
    @EnvironmentObject var sync: SyncCoordinator
    @AppStorage("autoLockSeconds") private var autoLockSeconds = 0
    @AppStorage("clipboardSeconds") private var clipboardSeconds = 30
    @State private var showingPassword = false
    @State private var showingRestorePicker = false
    @State private var showingExporter = false
    @State private var confirmingRestore = false
    @State private var restoreData: Data?
    @State private var document: EncryptedBackupDocument?
    @State private var exportName = ""
    @State private var busy = false
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                securitySection
                CustomSection("Data and synchronization") {
                    NavigationLink { VaultLocationView() } label: {
                        Label("Vault file location", systemImage: "folder")
                    }
                    NavigationLink { WebDAVView() } label: {
                        Label("WebDAV / S3 synchronization", systemImage: "arrow.triangle.2.circlepath")
                    }
                    NavigationLink { BitwardenImportView() } label: {
                        Label("Import from Bitwarden", systemImage: "square.and.arrow.down")
                    }.disabled(!store.canEdit)
                    Button { exportBackup() } label: {
                        Label("Export encrypted backup", systemImage: "square.and.arrow.up")
                    }
                    Button { showingRestorePicker = true } label: {
                        Label("Restore encrypted backup", systemImage: "arrow.counterclockwise")
                    }.disabled(!store.canEdit)
                    NavigationLink { LocalSyncBackupsView() } label: {
                        Label("Local synchronization backups", systemImage: "externaldrive.badge.timemachine")
                    }
                    Text("Encrypted backups include the vault and all attachments and restore the documents folder automatically. Each backup is limited to 512 MiB. WebDAV and S3 / R2 synchronize vault and attachment ciphertext; cloud-folder synchronization requires both vault.unipass and documents. Local backups are lost when app data is deleted.")
                        .customFont(.footnote).foregroundStyle(.secondary)
                }
                CustomSection("AutoFill") {
                    Label("System password AutoFill is not implemented", systemImage: "info.circle")
                    Text("For now, copy passwords inside the app. No system AutoFill extension is available.")
                        .customFont(.footnote).foregroundStyle(.secondary)
                }
                if busy { CustomSection { ProgressView("Processing encrypted backup…") } }
                if let message { CustomSection("Result") { Text(message).textSelection(.enabled) } }
                if let error = store.errorMessage {
                    CustomSection("Notice") { Text(error).foregroundStyle(.red).textSelection(.enabled) }
                }
            }
            .disabled(busy || sync.busy)
            .navigationTitle("Settings")
            .sheet(isPresented: $showingPassword) { ChangePasswordView() }
            .fileExporter(isPresented: $showingExporter, document: document,
                          contentType: .data, defaultFilename: exportName) { result in
                document = nil
                switch result {
                case .success: message = "The encrypted backup of the vault and all attachments was exported. Keep the file and its master password safe."
                case .failure(let error): message = "Export failed: \(error.localizedDescription)"
                }
            }
            .fileImporter(isPresented: $showingRestorePicker, allowedContentTypes: [.data]) { result in
                receiveRestore(result)
            }
            .alert("Replace the current vault?", isPresented: $confirmingRestore) {
                Button("Cancel", role: .cancel) { restoreData = nil }
                Button("Back up old vault and restore", role: .destructive) { restoreBackup() }
            } message: {
                Text("This replaces all current entries and folders and restores backup attachments without merging. The old vault and its attachments are backed up first; restoration stops if any attachment is missing, corrupted, or cannot be backed up. Older backups are supported, but attachments not included in them must remain local. Only a backup using the current master password can be restored. Synchronize manually and check for conflicts afterward.")
            }
        }
    }

    private var securitySection: some View {
        CustomSection {
            #if !targetEnvironment(macCatalyst)
            Toggle("Allow mobile editing", isOn: $store.allowMobileEditing)
            #endif
            Toggle("Unlock with Face ID / Touch ID", isOn: Binding(
                get: { store.biometricEnabled },
                set: { enabled in
                    do { try store.setBiometricEnabled(enabled) }
                    catch { store.errorMessage = "Biometric setting failed: \(error.localizedDescription)" }
                }
            ))
            Picker("Lock after entering background", selection: $autoLockSeconds) {
                Text("Immediately").tag(0)
                Text("After 30 seconds").tag(30)
                Text("After 1 minute").tag(60)
                Text("After 5 minutes").tag(300)
            }
            Picker("Clear clipboard after", selection: $clipboardSeconds) {
                Text("15 seconds").tag(15)
                Text("30 seconds").tag(30)
                Text("60 seconds").tag(60)
                Text("120 seconds").tag(120)
            }
            Button("Change master password") { showingPassword = true }.disabled(!store.canEdit)
        } header: {
            Text("Security")
        } footer: {
            Text("Mobile devices are read-only by default. Enable Allow Mobile Editing to add, edit, delete, and import; this affects only this device, not Mac. Background lock timeout is not an idle timer while the app is in the foreground. Biometrics unlock this device but cannot recover the master password. Clearing the clipboard does not overwrite content copied later.")
        }
    }

    private func exportBackup() {
        do {
            guard store.isUnlocked, !sync.busy else { throw VaultError.busy }
            document = EncryptedBackupDocument(data: try store.backupData())
            exportName = BackupFiles.exportName()
            showingExporter = true
        } catch { message = "Export failed: \(error.localizedDescription)" }
    }

    private func receiveRestore(_ result: Result<URL, Error>) {
        guard !busy, !sync.busy else { message = "Wait for the current operation to finish and try again."; return }
        switch result {
        case .failure(let error): message = "Backup selection failed: \(error.localizedDescription)"
        case .success(let url):
            busy = true
            message = nil
            Task { @MainActor in
                defer { busy = false }
                do {
                    let data = try await Task.detached(priority: .userInitiated) {
                        try BackupFiles.readScoped(url, maximumBytes: VaultBackup.maximumBytes)
                    }.value
                    guard store.isUnlocked else { throw VaultError.locked }
                    try VaultBackup.validate(data)
                    restoreData = data
                    confirmingRestore = true
                } catch { message = "Reading backup failed: \(error.localizedDescription)" }
            }
        }
    }

    private func restoreBackup() {
        guard let data = restoreData else { return }
        restoreData = nil
        guard !busy, !sync.busy, store.isUnlocked, store.canEdit else {
            message = "The vault is locked, read-only, or busy with another operation. Try again."
            return
        }
        busy = true
        Task { @MainActor in
            defer { busy = false }
            do {
                try await store.restoreBackupIntoCurrent(data)
                sync.clearConflict()
                message = "The vault and all backup attachments were restored. The old vault and its attachments are preserved in local synchronization backups for export and later restoration. It has not been synchronized remotely."
            } catch { message = "Restore failed: \(error.localizedDescription). The saved old-vault backup remains available." }
        }
    }
}

@MainActor
struct GeneratorView: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage("clipboardSeconds") private var clipboardSeconds = 30
    private let onUse: ((String) -> Void)?
    @State private var length = 20
    @State private var uppercase = true
    @State private var lowercase = true
    @State private var digits = true
    @State private var symbols = true
    @State private var password = ""
    @State private var errorMessage: String?
    @State private var copied = false

    init(onUse: ((String) -> Void)? = nil) { self.onUse = onUse }

    var body: some View {
        NavigationStack {
            Form {
                CustomSection("Generated password") {
                    if !password.isEmpty {
                        Text(verbatim: password)
                            .customFont(.title3)
                            .privacySensitive()
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .accessibilityLabel("Generated password: \(password)")
                    } else {
                        Text("Choose character types and generate a password").foregroundStyle(.secondary)
                    }
                    Button { generate() } label: {
                        Label("Generate again", systemImage: "arrow.clockwise")
                    }
                    Button {
                        SecureClipboard.copy(password, clearAfter: TimeInterval(clipboardSeconds))
                        copied = true
                    } label: {
                        Label(copied ? "Copied" : "Copy password", systemImage: copied ? "checkmark" : "doc.on.doc")
                    }
                    .disabled(password.isEmpty)
                    if let onUse {
                        Button("Use this password") { onUse(password); dismiss() }
                            .disabled(password.isEmpty)
                    }
                }
                CustomSection {
                    Stepper("Password length: \(length)", value: $length, in: 4...128)
                    Toggle("Uppercase letters", isOn: $uppercase)
                    Toggle("Lowercase letters", isOn: $lowercase)
                    Toggle("Digits", isOn: $digits)
                    Toggle("Symbols", isOn: $symbols)
                } header: { Text("Random options") } footer: {
                    Text("Uses the system secure random generator and guarantees at least one character from every selected group. The clipboard is cleared after about \(clipboardSeconds) seconds.")
                }
                if let errorMessage { CustomSection { Text(errorMessage).foregroundStyle(.red) } }
            }
            .navigationTitle("Password generator")
            .toolbar {
                if onUse != nil {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { onUse?(password); dismiss() }.disabled(password.isEmpty)
                    }
                }
            }
            .onAppear { if password.isEmpty { generate() } }
            .onChange(of: length) { _ in generate() }
            .onChange(of: uppercase) { _ in generate() }
            .onChange(of: lowercase) { _ in generate() }
            .onChange(of: digits) { _ in generate() }
            .onChange(of: symbols) { _ in generate() }
        }
    }

    private func generate() {
        copied = false
        do {
            password = try PasswordGenerator.generate(length: length, uppercase: uppercase,
                lowercase: lowercase, digits: digits, symbols: symbols)
            errorMessage = nil
        } catch {
            password = ""
            errorMessage = error.localizedDescription
        }
    }
}

@MainActor
struct WebDAVView: View {
    @EnvironmentObject var store: VaultStore
    @EnvironmentObject var sync: SyncCoordinator
    @State private var draft = WebDAVConfiguration()
    @State private var s3Draft = S3Configuration()
    @State private var draftBackend: SyncBackend = .webDAV
    @State private var loaded = false
    @State private var rememberCredentials = true
    @State private var resolution: ConflictResolution?

    private enum ConflictResolution: String, Identifiable {
        case remote, local
        var id: String { rawValue }
    }

    var body: some View {
        Form {
            CustomSection("Synchronization service") {
                Picker("Service type", selection: $draftBackend) {
                    Text("WebDAV").tag(SyncBackend.webDAV)
                    Text("S3 / Cloudflare R2").tag(SyncBackend.s3)
                }
            }
            CustomSection {
              if draftBackend == .webDAV {
                TextField("Full server directory URL", text: $draft.serverURL)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityHint("Use the HTTPS address of an existing directory")
                TextField("Username", text: $draft.username)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField("Password or app password", text: $draft.password)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Toggle("Allow insecure HTTP", isOn: $draft.allowInsecureHTTP)
                if draft.allowInsecureHTTP {
                    Label("Danger: HTTP exposes credentials and cannot protect traffic from interception or tampering. HTTPS is strongly recommended even when the vault is encrypted.", systemImage: "exclamationmark.triangle.fill")
                        .customFont(.footnote).foregroundStyle(.red)
                }
              } else {
                s3Fields
              }
                Toggle("Save credentials in local Keychain", isOn: $rememberCredentials)
                if !rememberCredentials {
                    Text("Used only for this unlock session. WebDAV passwords and S3 Secret Access Keys are cleared from memory when locked. Useful when the local signing environment does not support Keychain.")
                        .customFont(.footnote).foregroundStyle(.secondary)
                }
                Button(rememberCredentials ? "Save configuration" : "Apply for this session") { _ = saveDraft() }
                Button("Test connection") {
                    guard saveDraft() else { return }
                    Task { await sync.testConnection() }
                }
                Button("Synchronize now") {
                    guard saveDraft() else { return }
                    Task { await sync.synchronize(store: store) }
                }
            } header: { Text("Connection configuration") } footer: {
                Text(draftBackend == .webDAV
                                    ? "Enter an existing WebDAV directory. Credentials are stored in Keychain by default; when saving is disabled, they are used only for this session and existing Keychain data is not deleted."
                                    : "Create a bucket first and grant it object read/write access. R2 uses an S3 API endpoint and S3 Access Key, not an administrative API token or r2.dev URL. Credentials are stored in Keychain by default or can be used only for this session.")
            }
            CustomSection("Synchronization status") {
                if sync.busy { ProgressView("Connecting and synchronizing…") }
                if let date = sync.lastSync {
                    LabeledContent("Last successful synchronization") {
                        Text(date, format: .dateTime.year().month().day().hour().minute())
                    }
                } else { Text("No successful synchronization yet").foregroundStyle(.secondary) }
                if let message = sync.message { Text(message).textSelection(.enabled) }
            }
            if sync.hasConflict {
                CustomSection {
                    Button("Keep remote version and replace local", role: .destructive) { resolution = .remote }
                    Button("Keep local version and replace remote", role: .destructive) { resolution = .local }
                } header: { Text("Conflict requires a decision") } footer: {
                    Text("Items are not merged automatically. The replaced version is saved in local synchronization backups and can be exported and restored from Settings. Save configuration and synchronize again before resolving a conflict.")
                }
            }
            CustomSection("Synchronization details") {
                Text("Synchronizes vault.enc and attachment-UUID.enc ciphertext. All attachments are uploaded before conditionally committing the vault; downloads verify every attachment before replacing the local vault. Missing attachments are checked and repaired even when both vaults match. All devices must use the same master password.")
                Text("Use one vault per directory or bucket prefix. Remote attachments are not automatically deleted to protect other devices and historical versions; the server can still see ciphertext sizes, counts, and access times.")
                    .customFont(.footnote).foregroundStyle(.secondary)
                Text("Synchronization runs only when requested, not in the background. There is no device list or automatic merge. After changing the master password, coordinate other devices and backups first.")
                NavigationLink("View local synchronization backups") { LocalSyncBackupsView() }
            }
        }
        .disabled(sync.busy)
        .navigationTitle("Cloud synchronization")
        .onAppear {
            if !loaded {
                draft = sync.configuration
                s3Draft = sync.s3Configuration
                draftBackend = sync.backend
                loaded = true
            }
        }
        .onChange(of: store.isUnlocked) { unlocked in
            if !unlocked { draft.password = ""; s3Draft.secretAccessKey = "" }
        }
        .onDisappear { draft.password = ""; s3Draft.secretAccessKey = ""; loaded = false }
        .alert(item: $resolution) { choice in
            Alert(title: Text(choice == .remote ? "Use remote version?" : "Use local version?"),
                  message: Text(choice == .remote
                    ? "The current local vault will be fully replaced by the remote version. The old local version is saved as an encrypted backup; entries are not merged."
                    : "The remote vault will be fully replaced by the local version. The old remote version is saved as a local encrypted backup; entries are not merged."),
                  primaryButton: .destructive(Text("Confirm replacement")) {
                    guard !sync.busy else { return }
                    guard draftMatchesConfiguration else {
                        sync.message = "The configuration draft changed. Save it and synchronize again before resolving the conflict."
                        return
                    }
                    Task { await sync.resolve(useRemote: choice == .remote, store: store) }
                  }, secondaryButton: .cancel(Text("Cancel")))
        }
    }

    private var draftMatchesConfiguration: Bool {
        draftBackend == sync.backend && (draftBackend == .webDAV
            ? draft == sync.configuration : s3Draft == sync.s3Configuration)
    }

    private var s3Fields: some View {
        Group {
            TextField("S3 API endpoint (https://…)", text: $s3Draft.endpoint)
                .keyboardType(.URL)
            TextField("Bucket (existing bucket)", text: $s3Draft.bucket)
            TextField("Region (use auto for R2)", text: $s3Draft.region)
            TextField("Object prefix (optional, for example uniPass)", text: $s3Draft.prefix)
            TextField("Access Key ID", text: $s3Draft.accessKeyID)
            SecureField("Secret Access Key", text: $s3Draft.secretAccessKey).privacySensitive()
            Text("R2 endpoint example: https://account-id.r2.cloudflarestorage.com. Use auto for the region and omit leading or trailing slashes from the prefix. HTTPS, path-style requests, and AWS Signature V4 are used; temporary STS credentials are unsupported. Test connection checks read-only object listing under the prefix and does not upload a probe; it does not guarantee object write or conditional-write support.")
                .customFont(.footnote).foregroundStyle(.secondary)
        }.textInputAutocapitalization(.never).autocorrectionDisabled()
    }

    private func saveDraft() -> Bool {
        guard !sync.busy else { return false }
        let previous = sync.configuration
        let previousS3 = sync.s3Configuration
        let previousBackend = sync.backend
        sync.configuration = draft
        sync.s3Configuration = s3Draft
        sync.backend = draftBackend
        do {
            try sync.saveConfiguration(persistCredentials: rememberCredentials)
            sync.message = rememberCredentials ? "Configuration saved." : "Configuration applied for this session only."
            return true
        } catch {
            sync.configuration = previous
            sync.s3Configuration = previousS3
            sync.backend = previousBackend
            sync.message = "Saving configuration failed: \(error.localizedDescription). If the local signing environment does not support Keychain, disable Save credentials in Keychain and use the configuration only for this session."
            return false
        }
    }
}

@MainActor
struct BitwardenImportView: View {
    @EnvironmentObject var store: VaultStore
    @EnvironmentObject var sync: SyncCoordinator
    @State private var showingPicker = false
    @State private var showingDirectoryPicker = false
    @State private var attachmentsDirectory: URL?
    @State private var confirmingImport = false
    @State private var importData: Data?
    @State private var preview: BitwardenImportPreview?
    @State private var busy = false
    @State private var message: String?

    var body: some View {
        Form {
            CustomSection {
                Button("Choose Bitwarden JSON file") { showingPicker = true }
                Button("Choose extracted attachment export directory") { showingDirectoryPicker = true }
                Text("A regular JSON export does not contain attachment files. To import attachments, extract a Bitwarden .zip export containing attachments and choose the directory containing data.json and attachments. Legacy ID directories and uniquely matching name directories are supported; ambiguous names or missing attachments stop the import. JSON is limited to 50 MB, each attachment to 32 MiB, and each batch to 256 MiB. All processing happens locally.")
                    .customFont(.footnote).foregroundStyle(.secondary)
                Text("The source JSON is plaintext and may contain every password. Securely delete the source file and its copies after importing.")
                    .customFont(.footnote).foregroundStyle(.red)
            }
            if let preview {
                CustomSection("Import preview") {
                    LabeledContent("Entries", value: "\(preview.itemCount)")
                    LabeledContent("Folders", value: "\(preview.folderCount)")
                    LabeledContent("Non-login items", value: "\(preview.otherTypeCount)")
                    Text("Non-login types retain their original data and show it in notes. Only identical original data is deduplicated; different versions of one source item may remain as separate entries.")
                        .customFont(.footnote).foregroundStyle(.secondary)
                    Button("Confirm import into current vault") { confirmingImport = true }.disabled(!store.canEdit)
                    if attachmentsDirectory != nil { Text("Attachments in the directory will also be imported").customFont(.footnote) }
                }
            }
            if busy { CustomSection { ProgressView("Reading and checking…") } }
            if let message { CustomSection("Result") { Text(message).textSelection(.enabled) } }
        }
        .disabled(busy || sync.busy || !store.canEdit)
        .navigationTitle("Bitwarden import")
        .fileImporter(isPresented: $showingPicker, allowedContentTypes: [.json]) { result in
            receiveFile(result)
        }
        .fileImporter(isPresented: $showingDirectoryPicker, allowedContentTypes: [.folder]) { result in
            receiveDirectory(result)
        }
        .alert("Confirm import?", isPresented: $confirmingImport) {
            Button("Cancel", role: .cancel) { }
            Button("Import") { performImport() }
        } message: {
            Text("Previewed data will be added to the current vault without clearing existing entries. Check the data after import and securely remove the plaintext source file.")
        }
        .onDisappear { importData = nil; preview = nil; releaseDirectory() }
    }

    private func releaseDirectory() {
        attachmentsDirectory?.stopAccessingSecurityScopedResource()
        attachmentsDirectory = nil
    }

    private func receiveDirectory(_ result: Result<URL, Error>) {
        guard !busy, !sync.busy, store.canEdit else { return }
        releaseDirectory()
        importData = nil
        preview = nil
        message = nil
        do {
            let directory = try result.get()
            _ = directory.startAccessingSecurityScopedResource()
            attachmentsDirectory = directory
            let data = try VaultAttachmentDisk.read(directory.appendingPathComponent("data.json"), maximum: 50_000_000)
            preview = try BitwardenImporter.preview(data: data)
            importData = data
        } catch {
            releaseDirectory()
            message = "Preview failed: \(error.localizedDescription)"
        }
    }

    private func receiveFile(_ result: Result<URL, Error>) {
        releaseDirectory()
        importData = nil
        preview = nil
        message = nil
        guard !busy, !sync.busy else { message = "Wait for the current operation to finish and try again."; return }
        switch result {
        case .failure(let error): message = "File selection failed: \(error.localizedDescription)"
        case .success(let url):
            busy = true
            Task { @MainActor in
                defer { busy = false }
                do {
                    let result = try await Task.detached(priority: .userInitiated) {
                        let data = try BackupFiles.readScoped(url, maximumBytes: 50_000_000)
                        return (data, try BitwardenImporter.preview(data: data))
                    }.value
                    guard store.isUnlocked else { throw VaultError.locked }
                    importData = result.0
                    preview = result.1
                } catch { message = "Preview failed: \(error.localizedDescription)" }
            }
        }
    }

    private func performImport() {
        guard let data = importData, !busy, !sync.busy else { return }
        busy = true
        defer { busy = false }
        do {
            let count = try store.importBitwarden(data: data, attachmentsDirectory: attachmentsDirectory)
            releaseDirectory()
            sync.clearConflict()
            importData = nil
            preview = nil
            message = "Import completed with \(count) new entries. It has not been synchronized remotely."
        } catch { message = "Import failed: \(error.localizedDescription)" }
    }
}

@MainActor
struct ChangePasswordView: View {
    @EnvironmentObject var store: VaultStore
    @EnvironmentObject var sync: SyncCoordinator
    @Environment(\.dismiss) private var dismiss
    @State private var current = ""
    @State private var newPassword = ""
    @State private var confirmation = ""
    @State private var acknowledged = false
    @State private var confirming = false
    @State private var busy = false
    @State private var errorMessage: String?

    private var valid: Bool {
        !current.isEmpty && newPassword.count >= 12 && newPassword.utf8.count <= 4096
            && newPassword == confirmation && newPassword != current && acknowledged
    }

    var body: some View {
        NavigationStack {
            Form {
                CustomSection("Verify current master password") {
                    SecureField("Current master password", text: $current).textContentType(.password)
                }
                CustomSection {
                    SecureField("New master password (at least 12 characters)", text: $newPassword)
                        .textContentType(.newPassword)
                    SecureField("Confirm new master password", text: $confirmation)
                        .textContentType(.newPassword)
                    if !newPassword.isEmpty && newPassword.count < 12 {
                        Text("The new master password must contain at least 12 characters.").foregroundStyle(.red)
                    }
                    if !confirmation.isEmpty && confirmation != newPassword {
                        Text("The new master password confirmations do not match.").foregroundStyle(.red)
                    }
                    if !newPassword.isEmpty && newPassword == current {
                        Text("The new master password must differ from the current master password.").foregroundStyle(.red)
                    }
                } header: { Text("Set new master password") } footer: {
                    Text("Do not reuse a password from another website; length matters more than complex substitution rules.")
                }
                CustomSection("Important reminder") {
                    Text("A forgotten master password cannot be recovered. Biometrics are not a backup for the master password. Older encrypted backups still require the old password; changing it does not re-encrypt old backups or other devices.")
                        .foregroundStyle(.red)
                    Text("Synchronize manually after changing it and coordinate the new master password on other devices to avoid overwriting an older version that must be kept.")
                    Toggle("I have securely remembered the new master password and understand these risks", isOn: $acknowledged)
                }
                if busy { CustomSection { ProgressView("Re-encrypting vault…") } }
                if let errorMessage { CustomSection { Text(errorMessage).foregroundStyle(.red) } }
            }
            .textInputAutocapitalization(.never).autocorrectionDisabled()
            .disabled(busy || sync.busy)
            .navigationTitle("Change master password")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(busy)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { confirming = true }.disabled(!valid || busy || sync.busy)
                }
            }
            .interactiveDismissDisabled(busy)
            .alert("Confirm master password change?", isPresented: $confirming) {
                Button("Cancel", role: .cancel) { }
                Button("Change master password", role: .destructive) { changePassword() }
            } message: {
                Text("The current vault will be re-encrypted with the new master password. A forgotten new password cannot be recovered; older backups still use the old password.")
            }
            .onDisappear { current = ""; newPassword = ""; confirmation = "" }
        }
    }

    private func changePassword() {
        guard valid, !busy, !sync.busy else { return }
        busy = true
        errorMessage = nil
        Task { @MainActor in
            defer { busy = false }
            do {
                try await store.changePassword(current: current, new: newPassword)
                sync.clearConflict()
                current = ""; newPassword = ""; confirmation = ""
                dismiss()
            } catch { errorMessage = "Change failed: \(error.localizedDescription)" }
        }
    }
}

@MainActor
private struct LocalSyncBackupsView: View {
    @EnvironmentObject var store: VaultStore
    @EnvironmentObject var sync: SyncCoordinator
    @State private var backups: [BackupFiles.Record] = []
    @State private var pendingDelete: BackupFiles.Record?
    @State private var confirmingDelete = false
    @State private var showingExporter = false
    @State private var document: EncryptedBackupDocument?
    @State private var exportName = ""
    @State private var message: String?

    var body: some View {
        List {
            CustomSection {
                Text("New local backups contain that vault version and all of its attachments. Export the version you need, then return to Settings and choose Restore Encrypted Backup. Restoration replaces the entire vault without merging. Older backups may not contain attachments, and missing files cannot be recovered from them.")
                Text("Only the current master password can restore a backup. If it predates a password change, keep the file and its old password and restore it in a fresh installation without a vault.")
                    .customFont(.footnote).foregroundStyle(.secondary)
            }
            CustomSection("Local encrypted versions (\(backups.count))") {
                if backups.isEmpty { Text("No local synchronization backups").foregroundStyle(.secondary) }
                ForEach(backups) { backup in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(backup.date, format: .dateTime.year().month().day().hour().minute().second())
                        Text(backup.url.lastPathComponent)
                            .customFont(.caption).foregroundStyle(.secondary)
                            .lineLimit(2).textSelection(.enabled)
                        HStack {
                            Text(ByteCountFormatter.string(fromByteCount: backup.size, countStyle: .file))
                                .customFont(.caption).foregroundStyle(.secondary)
                            Spacer()
                            Button("Export") { export(backup) }.buttonStyle(.bordered)
                            Button("Delete", role: .destructive) {
                                pendingDelete = backup; confirmingDelete = true
                            }.buttonStyle(.bordered)
                        }
                    }.padding(.vertical, 4)
                }
            }
            if let message { CustomSection("Notice") { Text(message).textSelection(.enabled) } }
        }
        .disabled(sync.busy)
        .navigationTitle("Local synchronization backups")
        .onAppear { reload() }
        .toolbar { ToolbarItem(placement: .primaryAction) { Button("Refresh") { reload() } } }
        .fileExporter(isPresented: $showingExporter, document: document,
                      contentType: .data, defaultFilename: exportName) { result in
            document = nil
            switch result {
            case .success: message = "The encrypted version was exported. Use the master password associated with this version to restore it."
            case .failure(let error): message = "Export failed: \(error.localizedDescription)"
            }
        }
        .alert("Permanently delete this local backup?", isPresented: $confirmingDelete) {
            Button("Cancel", role: .cancel) { pendingDelete = nil }
            Button("Delete permanently", role: .destructive) { deletePending() }
        } message: {
            Text("Deletion cannot be undone. Export it first if it contains conflict data you need; this does not delete the current vault or remote files.")
        }
    }

    private func reload() {
        do { backups = try BackupFiles.records(vaultURL: store.vaultURL, directory: store.backupDirectory) }
        catch { message = "Reading backup list failed: \(error.localizedDescription)" }
    }

    private func export(_ backup: BackupFiles.Record) {
        do {
            document = EncryptedBackupDocument(data: try BackupFiles.read(backup.url,
                maximumBytes: VaultBackup.maximumBytes))
            exportName = BackupFiles.exportName(date: backup.date)
            showingExporter = true
        } catch { message = "Reading backup failed: \(error.localizedDescription)" }
    }

    private func deletePending() {
        guard let backup = pendingDelete, !sync.busy else { return }
        pendingDelete = nil
        do {
            try FileManager.default.removeItem(at: backup.url)
            message = "The selected local encrypted backup was deleted."
            reload()
        } catch { message = "Deletion failed: \(error.localizedDescription)" }
    }
}

@MainActor
struct VaultLocationView: View {
    @EnvironmentObject private var store: VaultStore
    @EnvironmentObject private var sync: SyncCoordinator
    @Environment(\.dismiss) private var dismiss
    @State private var choosing = false
    @State private var copying = false
    @State private var pendingDirectory: URL?
    @State private var pendingAccess = false
    @State private var confirming = false
    @State private var confirmingDefault = false
    @State private var message: String?

    var body: some View {
        Form {
            CustomSection("Current vault file") {
                Text(store.vaultURL.path).customFont(.footnote).textSelection(.enabled)
                Text(store.usesCustomLocation ? "Custom directory" : "Local default directory").foregroundStyle(.secondary)
                Button { SecureClipboard.copy(store.vaultURL.path) } label: { Label("Copy file path", systemImage: "doc.on.doc") }
                if let error = store.locationError { Text(error).foregroundStyle(.red) }
            }
            CustomSection {
                Button("Copy the current vault and switch to another directory…") {
                    copying = true; choosing = true
                }.disabled(!store.isUnlocked || store.externalChangeMessage != nil)
                Button("Open an existing vault in another directory…") {
                    copying = false; choosing = true
                }
                if store.usesCustomLocation {
                    Button("Reopen the local default location…") { confirmingDefault = true }
                }
            } header: { Text("Choose file location") } footer: {
                Text("Choose a directory, not an individual file. The filename is vault.unipass. Copying preserves the source and does not overwrite an existing target vault; unlock again after switching. On another computer, choose Open an Existing Vault instead of creating an empty one.")
            }
            CustomSection("Using Dropbox or another cloud drive") {
                Text("Create a dedicated uniPass directory in the cloud drive and keep it available locally. The app reads and writes encrypted files directly while the cloud client transfers them.")
                Text("Synchronization is not a backup. Offline simultaneous edits can create conflict copies; uniPass does not merge or delete them automatically. Synchronize before editing, wait for the upload to finish, and then switch computers.")
                    .foregroundStyle(.orange)
                Text("The app checks for external changes every 5 seconds and when returning to the foreground, then checks the disk version again before saving. When a change is found, writes pause, a local encrypted backup of the last committed version is retained, and reopening is requested.")
                Text("Local conflict backups remain in the default Application Support directory and do not move with the selected cloud directory. Do not synchronize the same working vault bidirectionally with both Dropbox and WebDAV / S3; export an encrypted backup manually as a second safeguard.")
            }
            if let message { CustomSection("Notice") { Text(message).foregroundStyle(.red) } }
        }
        .navigationTitle("Vault file location")
        .disabled(sync.busy)
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.folder]) { result in
            releaseDirectory()
            do {
                let directory = try result.get()
                pendingAccess = directory.startAccessingSecurityScopedResource()
                pendingDirectory = directory
                confirming = true
            } catch { message = error.localizedDescription }
        }
        .alert(copying ? "Copy and switch vault?" : "Open existing vault?", isPresented: $confirming) {
            Button("Cancel", role: .cancel) { releaseDirectory() }
            Button("Confirm switch") { applyDirectory() }
        } message: {
            Text((pendingDirectory?.path ?? "") + (copying
                ? "\nThe currently saved encrypted data will be copied. The source remains and an existing target vault is not overwritten."
                : "\nThe vault.unipass file in this directory will be opened; the current vault remains unchanged. Close unsaved edits and enter the selected vault's master password."))
        }
        .alert("Reopen the local default location?", isPresented: $confirmingDefault) {
            Button("Cancel", role: .cancel) { }
            Button("Open default location") {
                do { try store.useDefaultDirectory(); sync.cancelPending(); dismiss() }
                catch { message = error.localizedDescription }
            }
        } message: {
            Text("This does not migrate or merge data back to the local location. Cloud files remain unchanged; the default location may still contain the previous version, so check the contents before using it.")
        }
        .onDisappear { releaseDirectory() }
    }

    private func applyDirectory() {
        guard let directory = pendingDirectory, !sync.busy else { return }
        defer { releaseDirectory() }
        do {
            if copying { try store.copyToDirectory(directory) }
            else { try store.openDirectory(directory) }
            sync.cancelPending()
            dismiss()
        } catch { message = error.localizedDescription }
    }

    private func releaseDirectory() {
        if pendingAccess { pendingDirectory?.stopAccessingSecurityScopedResource() }
        pendingAccess = false
        pendingDirectory = nil
    }
}

enum BackupFiles {
    struct Record: Identifiable {
        var id: URL { url }
        let url: URL
        let date: Date
        let size: Int64
    }

    static func exportName(date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        return "uniPass-\(formatter.string(from: date)).enc"
    }

    static func directory(vaultURL: URL) -> URL {
        vaultURL.deletingLastPathComponent().appendingPathComponent("Sync Backups", isDirectory: true)
    }

    static func readScoped(_ url: URL, maximumBytes: Int) throws -> Data {
        let granted = url.startAccessingSecurityScopedResource()
        defer { if granted { url.stopAccessingSecurityScopedResource() } }
        var coordinationError: NSError?
        var result: Result<Data, Error>?
        NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { coordinatedURL in
            result = Result { try read(coordinatedURL, maximumBytes: maximumBytes) }
        }
        if let coordinationError { throw coordinationError }
        guard let result else { throw CocoaError(.fileReadUnknown) }
        return try result.get()
    }

    static func read(_ url: URL, maximumBytes: Int) throws -> Data {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true else { throw VaultError.invalidEnvelope }
        if let size = values.fileSize, size > maximumBytes { throw VaultError.dataTooLarge }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        guard data.count <= maximumBytes else { throw VaultError.dataTooLarge }
        return data
    }


    static func records(vaultURL: URL, directory: URL? = nil) throws -> [Record] {
        let folder = directory ?? self.directory(vaultURL: vaultURL)
        guard FileManager.default.fileExists(atPath: folder.path) else { return [] }
        let keys: Set<URLResourceKey> = [.isRegularFileKey, .isSymbolicLinkKey, .creationDateKey, .contentModificationDateKey, .fileSizeKey]
        return try FileManager.default.contentsOfDirectory(at: folder,
            includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles])
            .filter { $0.pathExtension.lowercased() == "enc" }
            .compactMap { url -> Record? in
                let values = try url.resourceValues(forKeys: keys)
                guard values.isRegularFile == true, values.isSymbolicLink != true else { return nil }
                return Record(url: url, date: values.creationDate ?? values.contentModificationDate ?? .distantPast,
                              size: Int64(values.fileSize ?? 0))
            }
            .sorted { $0.date > $1.date }
    }
}

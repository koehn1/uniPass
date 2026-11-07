import SwiftUI
import AVFoundation
import CoreImage
import UniformTypeIdentifiers

struct AttachmentDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents,
              data.count <= VaultCrypto.maximumAttachmentBytes else { throw VaultError.dataTooLarge }
        self.data = data
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

struct EntryDetailView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @AppStorage("clipboardSeconds") private var clipboardSeconds = 30
    let entryID: UUID
    @State private var editing: VaultEntry?
    @State private var showPassword = false
    @State private var showOriginal = false
    @State private var confirmDelete = false
    @State private var confirmDeleteOriginal = false
    @State private var showingAttachmentPicker = false
    @State private var deletingAttachment: VaultAttachment?
    @State private var exportAttachment: AttachmentDocument?
    @State private var exportAttachmentName = ""
    @State private var showingAttachmentExporter = false
    @State private var attachmentMessage: String?
    @State private var copied: String?

    private var entry: VaultEntry? { store.payload.entries.first { $0.id == entryID } }

    var body: some View {
        Group {
            if let entry {
                List {
                    CustomSection {
                        VStack(spacing: 10) {
                            SiteIcon(name: entry.name, size: 68)
                            Text(entry.name).customFont(.title2)
                            Label((store.payload.folders.first { $0.id == entry.folderID }?.name ?? "Uncategorized") + (entry.favorite ? " · Favorite" : ""), systemImage: "folder")
                                .customFont(.footnote).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity).padding(.vertical, 12)
                    }.listRowBackground(Color.clear)
                    CustomSection {
                        valueRow("Username / email", value: entry.username)
                        HStack {
                            VStack(alignment: .leading, spacing: 5) {
                                Text("Password").customFont(.caption).foregroundStyle(.secondary)
                                Text(showPassword ? (entry.password.isEmpty ? "Not set" : entry.password) : "••••••••••••")
                                    .customFont(.body).privacySensitive()
                            }
                            Spacer()
                            Button { showPassword.toggle() } label: { Image(systemName: showPassword ? "eye.slash" : "eye") }
                                .accessibilityLabel(showPassword ? "Hide password" : "Show password")
                            Button { copy(entry.password, label: "Password") } label: { Image(systemName: "doc.on.doc") }
                                .accessibilityLabel("Copy password").disabled(entry.password.isEmpty)
                        }.buttonStyle(.borderless).padding(.vertical, 4)
                        ForEach(Array(entry.urls.enumerated()), id: \.offset) { _, address in
                            HStack {
                                VStack(alignment: .leading, spacing: 5) {
                                    Text("Website").customFont(.caption).foregroundStyle(.secondary)
                                    if let url = Self.webURL(address) { Link(address, destination: url) }
                                    else { Text(address) }
                                }
                                Spacer()
                                Button { copy(address, label: "Website") } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless)
                            }
                        }
                    }
                    if !entry.totp.isEmpty {
                        CustomSection("Two-factor authentication · TOTP") { TOTPCodeView(secret: entry.totp, clearAfter: Double(clipboardSeconds)) }
                    }
                    if !entry.fields.isEmpty {
                        CustomSection("Custom fields") {
                            ForEach(entry.fields) { field in CustomFieldRow(field: field, clearAfter: Double(clipboardSeconds)) }
                        }
                    }
                    if !entry.notes.isEmpty {
                        CustomSection("Notes") {
                            Text(entry.notes).customFont(.body).privacySensitive()
                            Button { copy(entry.notes, label: "Notes") } label: { Label("Copy notes", systemImage: "doc.on.doc") }
                        }
                    }
                    attachmentSection(entry)
                    if let original = entry.originalJSON {
                        CustomSection {
                            DisclosureGroup("Original Bitwarden data (contains sensitive content)", isExpanded: $showOriginal) {
                                Text(original).customFont(.caption).privacySensitive()
                                Button { copy(original, label: "Original data") } label: { Label("Copy original JSON", systemImage: "doc.on.doc") }
                                if store.canEdit {
                                    Button("Delete original JSON", role: .destructive) { confirmDeleteOriginal = true }
                                }
                            }
                        } footer: { Text("Imported extra fields are retained. Editing the fields above does not rewrite the original snapshot, so it may differ from the current content. Deleting the snapshot does not delete current fields or attachments; notes for non-login types may still contain imported data.") }
                    }
                    CustomSection {
                        LabeledContent("Created", value: entry.createdAt.formatted(date: .abbreviated, time: .shortened))
                        LabeledContent("Modified", value: entry.modifiedAt.formatted(date: .abbreviated, time: .shortened))
                    }.customFont(.footnote).foregroundStyle(.secondary)
                    if store.canEdit {
                      CustomSection {
                        if entry.deletedAt == nil {
                            Button {
                                var updated = entry; updated.favorite.toggle()
                                perform { try store.save(updated) }
                            } label: { Label(entry.favorite ? "Remove favorite" : "Add to favorites", systemImage: entry.favorite ? "star.slash" : "star") }
                            Button(role: .destructive) { confirmDelete = true } label: { Label("Move to Recently Deleted", systemImage: "trash") }
                        } else {
                            Button { perform { try store.restore(id: entry.id) }; dismiss() } label: { Label("Restore entry", systemImage: "arrow.uturn.backward") }
                            Button("Delete permanently", role: .destructive) { confirmDelete = true }
                        }
                      }
                    }
                }
                .listStyle(.insetGrouped)
                .toolbar {
                    if entry.deletedAt == nil && store.canEdit {
                        ToolbarItem(placement: .navigationBarTrailing) { Button("Edit") { editing = entry } }
                    }
                }
                .confirmationDialog(entry.deletedAt == nil ? "Move entry to Recently Deleted?" : "This cannot be undone", isPresented: $confirmDelete, titleVisibility: .visible) {
                    Button(entry.deletedAt == nil ? "Move to Recently Deleted" : "Delete permanently", role: .destructive) {
                        do {
                            if entry.deletedAt == nil { try store.trash(id: entry.id) }
                            else { try store.permanentlyDelete(id: entry.id) }
                            dismiss()
                        } catch { store.errorMessage = error.localizedDescription }
                    }
                }
            } else {
                Text("The entry was deleted or no longer exists").foregroundStyle(.secondary)
            }
        }
        .navigationTitle("").navigationBarTitleDisplayMode(.inline)
        .sheet(item: $editing) { EntryEditorView(entry: $0) }
        .fileImporter(isPresented: $showingAttachmentPicker, allowedContentTypes: [.data]) { result in
            perform { try store.addAttachment(entryID: entryID, from: result.get()) }
        }
        .fileExporter(isPresented: $showingAttachmentExporter, document: exportAttachment,
                      contentType: .data, defaultFilename: exportAttachmentName) { result in
            exportAttachment = nil
            if case .failure(let error) = result { attachmentMessage = error.localizedDescription }
        }
        .confirmationDialog("Delete original Bitwarden JSON?", isPresented: $confirmDeleteOriginal, titleVisibility: .visible) {
            Button("Delete original JSON", role: .destructive) { perform { try store.removeOriginalJSON(id: entryID) } }
        } message: { Text("Only the current entry's original snapshot will be deleted. This cannot be undone. Current fields, notes, attachments, and existing backup data are unchanged.") }
        .confirmationDialog("Delete attachment?", isPresented: Binding(get: { deletingAttachment != nil }, set: { if !$0 { deletingAttachment = nil } }), titleVisibility: .visible) {
            Button("Delete attachment", role: .destructive) {
                if let attachment = deletingAttachment { perform { try store.removeAttachment(entryID: entryID, attachmentID: attachment.id) } }
                deletingAttachment = nil
            }
        } message: { Text("The attachment file will be deleted. This cannot be undone.") }
        .alert("Attachment notice", isPresented: Binding(get: { attachmentMessage != nil }, set: { if !$0 { attachmentMessage = nil } })) {
            Button("OK", role: .cancel) { attachmentMessage = nil }
        } message: { Text(attachmentMessage ?? "") }
        .alert("Copied \(copied ?? "")", isPresented: Binding(get: { copied != nil }, set: { if !$0 { copied = nil } })) {
            Button("OK", role: .cancel) { copied = nil }
        } message: { Text("The clipboard will expire in \(clipboardSeconds) seconds.") }
        .onDisappear { showPassword = false; showOriginal = false; exportAttachment = nil }
        .onChange(of: store.isUnlocked) { unlocked in
            if !unlocked { exportAttachment = nil; showingAttachmentExporter = false }
        }
    }

    private func attachmentSection(_ entry: VaultEntry) -> some View {
        CustomSection {
            ForEach(entry.attachments) { attachment in
                VStack(alignment: .leading, spacing: 8) {
                    Label(attachment.fileName, systemImage: "paperclip").privacySensitive()
                    Text(ByteCountFormatter.string(fromByteCount: attachment.byteCount, countStyle: .file))
                        .customFont(.caption).foregroundStyle(.secondary)
                    HStack {
                        Button("Export attachment") {
                            do {
                                exportAttachment = AttachmentDocument(data: try store.attachmentData(entryID: entryID, attachmentID: attachment.id))
                                exportAttachmentName = attachment.fileName
                                showingAttachmentExporter = true
                            } catch { attachmentMessage = error.localizedDescription }
                        }
                        if store.canEdit && entry.deletedAt == nil {
                            Spacer()
                            Button("Delete", role: .destructive) { deletingAttachment = attachment }
                        }
                    }.buttonStyle(.borderless)
                }.padding(.vertical, 4)
            }
            if entry.attachments.isEmpty { Text("No attachments").foregroundStyle(.secondary) }
            if store.canEdit && entry.deletedAt == nil {
                Button { showingAttachmentPicker = true } label: { Label("Add attachment", systemImage: "plus.circle") }
            }
        } header: { Text("Attachments") } footer: {
            Text("Attachments are encrypted in the documents folder next to the vault, with a 32 MiB limit per file. Encrypted backups and WebDAV / S3 synchronization include attachment ciphertext. Direct cloud-folder synchronization requires both vault.unipass and documents. Exported attachments are plaintext; store them carefully.")
        }
    }

    private func valueRow(_ label: String, value: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 5) {
                Text(label).customFont(.caption).foregroundStyle(.secondary)
                Text(value.isEmpty ? "Not set" : value).privacySensitive()
            }
            Spacer()
            Button { copy(value, label: label) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless).disabled(value.isEmpty)
        }.padding(.vertical, 4)
    }

    private func copy(_ value: String, label: String) { SecureClipboard.copy(value, clearAfter: Double(clipboardSeconds)); copied = label }
    private func perform(_ action: () throws -> Void) { do { try action() } catch { store.errorMessage = error.localizedDescription } }
    private static func webURL(_ address: String) -> URL? {
        guard let url = URL(string: address.contains("://") ? address : "https://" + address),
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""), url.host != nil else { return nil }
        return url
    }
}

struct TOTPCodeView: View {
    let secret: String
    var clearAfter: TimeInterval = 30
    @State private var copied = false
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = Result { try TOTP.code(secret: secret, date: context.date) }
            switch code {
            case .success(let value):
                HStack {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(copied ? "Copied" : "One-time code").customFont(.caption).foregroundStyle(.secondary)
                        Text(value).customFont(size: 30, relativeTo: .title)
                            .foregroundStyle(.tint).privacySensitive().accessibilityLabel("One-time code " + value)
                    }
                    Spacer()
                    let remaining = TOTP.remaining(secret: secret, date: context.date)
                    ZStack {
                        Circle().stroke(Color.accentColor.opacity(0.15), lineWidth: 3)
                        Circle().trim(from: 0, to: remaining / Double(TOTP.period(secret: secret)))
                            .stroke(Color.accentColor, style: StrokeStyle(lineWidth: 3, lineCap: .round)).rotationEffect(.degrees(-90))
                        Text("\(Int(ceil(remaining)))").customFont(.caption2)
                    }.frame(width: 34, height: 34).accessibilityLabel("\(Int(ceil(remaining))) seconds remaining")
                    Button {
                        SecureClipboard.copy(value, clearAfter: min(clearAfter, remaining)); copied = true
                    } label: { Image(systemName: "doc.on.doc").padding(.leading, 8) }.buttonStyle(.borderless).accessibilityLabel("Copy one-time code")
                }.padding(.vertical, 6)
            case .failure(let error):
                Label(error.localizedDescription, systemImage: "exclamationmark.triangle").customFont(.footnote).foregroundStyle(.orange)
            }
        }
    }
}

private struct CustomFieldRow: View {
    let field: CustomField
    let clearAfter: TimeInterval
    @State private var revealed = false
    @State private var copied = false
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 5) {
                Text(field.name.isEmpty ? "Custom field" : field.name).customFont(.caption).foregroundStyle(.secondary)
                Text(field.type == 1 && !revealed ? "••••••••" : field.value).privacySensitive()
                if field.type == 3 { Text("Linked field · imported value retained").customFont(.caption2).foregroundStyle(.secondary) }
                if copied { Text("Copied").customFont(.caption2).foregroundStyle(.tint) }
            }
            Spacer()
            if field.type == 1 { Button { revealed.toggle() } label: { Image(systemName: revealed ? "eye.slash" : "eye") } }
            Button { SecureClipboard.copy(field.value, clearAfter: clearAfter); copied = true } label: { Image(systemName: "doc.on.doc") }
        }.buttonStyle(.borderless)
    }
}

struct EntryEditorView: View {
    @EnvironmentObject private var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @State var entry: VaultEntry
    @State private var urlText: String
    @State private var showPassword = false
    @State private var showGenerator = false
    @State private var scanning = false
    @State private var importQR = false
    @State private var discard = false
    @State private var error: String?
    private let original: VaultEntry
    private let isNew: Bool

    init(entry: VaultEntry, isNew: Bool = false) {
        self.original = entry
        self.isNew = isNew
        _entry = State(initialValue: entry)
        _urlText = State(initialValue: entry.urls.joined(separator: "\n"))
    }

    private var dirty: Bool { entry != original || urlText != original.urls.joined(separator: "\n") }

    var body: some View {
        NavigationStack {
            Form {
                CustomSection("Basic information") {
                    TextField("Name (for example, GitHub)", text: $entry.name)
                    TextField("Username / email", text: $entry.username).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Picker("Folder", selection: $entry.folderID) {
                        Text("Uncategorized").tag(Optional<UUID>.none)
                        ForEach(store.payload.folders) { Text($0.name).tag(Optional($0.id)) }
                    }
                    Toggle("Add to favorites", isOn: $entry.favorite)
                }
                CustomSection {
                    TextField("https://example.com, one per line", text: $urlText, axis: .vertical)
                        .lineLimit(2...5).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                } header: { Text("Websites") } footer: { Text("Multiple websites are supported and all imported URLs are retained.") }
                CustomSection("Password") {
                    HStack {
                        Group {
                            if showPassword { TextField("Password", text: $entry.password) }
                            else { SecureField("Password", text: $entry.password) }
                        }.textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button { showPassword.toggle() } label: { Image(systemName: showPassword ? "eye.slash" : "eye") }.buttonStyle(.borderless)
                    }
                    let strength = PasswordGenerator.strength(entry.password)
                    HStack {
                        ProgressView(value: strength.score).tint(strength.score < 0.3 ? .orange : .accentColor)
                        Text(strength.label).customFont(.caption).foregroundStyle(.secondary)
                    }
                    Button { showGenerator = true } label: { Label("Generate secure password", systemImage: "wand.and.stars") }
                }
                CustomSection {
                    TextField("Base32 secret or otpauth://totp/…", text: $entry.totp, axis: .vertical)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().lineLimit(2...4).privacySensitive()
                    if !entry.totp.isEmpty { TOTPCodeView(secret: entry.totp) }
                    #if !targetEnvironment(macCatalyst)
                    Button { scanning = true } label: { Label("Scan QR code", systemImage: "qrcode.viewfinder") }
                    #endif
                    Button { importQR = true } label: { Label("Read from QR image", systemImage: "photo") }
                } header: { Text("Two-factor authentication · TOTP") } footer: { Text("Supports SHA1 / SHA256 / SHA512 and 6- or 8-digit codes. The secret is stored with the password; assess the risk.") }
                CustomSection("Notes") {
                    TextEditor(text: $entry.notes).frame(minHeight: 110).privacySensitive()
                }
                CustomSection {
                    ForEach($entry.fields) { $field in
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                TextField("Field name", text: $field.name)
                                Button(role: .destructive) { entry.fields.removeAll { $0.id == field.id } }
                                label: { Image(systemName: "minus.circle.fill") }.buttonStyle(.borderless)
                            }
                            Picker("Type", selection: $field.type) {
                                Text("Text").tag(0); Text("Hidden").tag(1); Text("Boolean").tag(2)
                                if field.type == 3 { Text("Linked (imported value)").tag(3) }
                            }
                            if field.type == 1 { SecureField("Field value", text: $field.value) }
                            else if field.type == 2 {
                                Toggle("Value", isOn: Binding(get: { field.value.lowercased() == "true" }, set: { field.value = $0 ? "true" : "false" }))
                            } else { TextField("Field value", text: $field.value, axis: .vertical).textInputAutocapitalization(.never).autocorrectionDisabled() }
                        }.padding(.vertical, 5)
                    }
                    Button { entry.fields.append(CustomField()) } label: { Label("Add field", systemImage: "plus.circle") }
                } header: { Text("Custom fields") } footer: {
                    if entry.originalJSON != nil { Text("The original Bitwarden JSON is retained. Changes here affect the current uniPass fields and do not discard the original snapshot.") }
                }
                if let error { CustomSection { Text(error).foregroundStyle(.red).customFont(.footnote) } }
            }
            .disabled(!store.canEdit)
            .navigationTitle(store.payload.entries.contains { $0.id == entry.id } ? "Edit entry" : "New entry")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { if dirty { discard = true } else { dismiss() } } }
                ToolbarItem(placement: .confirmationAction) { Button("Save", action: save).customFont(.headline).disabled(!store.canEdit || entry.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) }
            }
            .confirmationDialog("Discard unsaved changes?", isPresented: $discard, titleVisibility: .visible) {
                Button("Discard changes", role: .destructive) { dismiss() }
            }
            .sheet(isPresented: $showGenerator) { GeneratorView(onUse: { entry.password = $0; showGenerator = false }) }
            .sheet(isPresented: $scanning) {
                QRScannerView { result in
                    scanning = false
                    switch result {
                    case .success(let value): applyQR(value)
                    case .failure(let error): self.error = error.localizedDescription
                    }
                }
            }
            .fileImporter(isPresented: $importQR, allowedContentTypes: [.image]) { result in
                do {
                    let url = try result.get()
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 20_000_000 else { throw VaultError.dataTooLarge }
                    guard let image = CIImage(data: try Data(contentsOf: url)),
                          let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]),
                          let value = detector.features(in: image).compactMap({ ($0 as? CIQRCodeFeature)?.messageString }).first else {
                        throw QRScanError.noCode
                    }
                    applyQR(value)
                } catch { self.error = error.localizedDescription }
            }
        }
        .interactiveDismissDisabled(dirty)
    }

    private func applyQR(_ value: String) {
        do { _ = try TOTP.code(secret: value); entry.totp = value; error = nil }
        catch { self.error = error.localizedDescription }
    }

    private func save() {
        do {
            let current = store.payload.entries.first { $0.id == original.id }
            guard isNew ? current == nil : current == original else {
                error = "This entry was changed by synchronization or another window. Close the editor and reopen it before making changes to avoid overwriting the newer version."
                return
            }
            var next = entry
            next.name = next.name.trimmingCharacters(in: .whitespacesAndNewlines)
            next.urls = urlText.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            next.totp = next.totp.trimmingCharacters(in: .whitespacesAndNewlines)
            // Imported non-standard OTP secrets may be retained; newly entered ones must validate.
            if !next.totp.isEmpty && next.totp != original.totp { _ = try TOTP.code(secret: next.totp) }
            try store.save(next)
            dismiss()
        } catch { self.error = error.localizedDescription }
    }
}

private enum QRScanError: LocalizedError {
    case unavailable, noCode
    var errorDescription: String? {
        switch self {
        case .unavailable: return "The camera is unavailable or unauthorized. Allow camera access in System Settings or read a QR code image."
        case .noCode: return "No readable QR code was found in the image."
        }
    }
}

private struct QRScannerView: View {
    @Environment(\.dismiss) private var dismiss
    let completion: (Result<String, Error>) -> Void
    var body: some View {
        NavigationStack {
            CameraScanner(completion: completion)
                .overlay(alignment: .bottom) {
                    Text("Place the TOTP QR code in the frame\nRecognition happens entirely on this device")
                        .multilineTextAlignment(.center).foregroundStyle(.white)
                        .padding().background(.black.opacity(0.65), in: RoundedRectangle(cornerRadius: 12)).padding(30)
                }
                .navigationTitle("Scan QR code").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
}

private struct CameraScanner: UIViewControllerRepresentable {
    let completion: (Result<String, Error>) -> Void
    func makeUIViewController(context: Context) -> ScannerController { ScannerController(completion: completion) }
    func updateUIViewController(_ uiViewController: ScannerController, context: Context) { }
    static func dismantleUIViewController(_ uiViewController: ScannerController, coordinator: ()) { uiViewController.stop() }
}

private final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let capture = AVCaptureSession()
    private let queue = DispatchQueue(label: "uniPass.camera")
    private var preview: AVCaptureVideoPreviewLayer?
    private var finished = false
    private var stopped = false
    private let completion: (Result<String, Error>) -> Void

    init(completion: @escaping (Result<String, Error>) -> Void) { self.completion = completion; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        AVCaptureDevice.requestAccess(for: .video) { [weak self] allowed in
            DispatchQueue.main.async {
                guard let self, !self.stopped else { return }
                guard allowed else { self.finish(.failure(QRScanError.unavailable)); return }
                self.configure()
            }
        }
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    private func configure() {
        do {
            guard let device = AVCaptureDevice.default(for: .video) else { throw QRScanError.unavailable }
            let input = try AVCaptureDeviceInput(device: device)
            let output = AVCaptureMetadataOutput()
            guard capture.canAddInput(input), capture.canAddOutput(output) else { throw QRScanError.unavailable }
            capture.addInput(input); capture.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            guard output.availableMetadataObjectTypes.contains(.qr) else { throw QRScanError.unavailable }
            output.metadataObjectTypes = [.qr]
            let layer = AVCaptureVideoPreviewLayer(session: capture)
            layer.videoGravity = .resizeAspectFill
            layer.frame = view.bounds; view.layer.addSublayer(layer); preview = layer
            queue.async { [capture] in capture.startRunning() }
        } catch { finish(.failure(error)) }
    }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        if let value = metadataObjects.compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }).first { finish(.success(value)) }
    }
    private func finish(_ result: Result<String, Error>) {
        guard !finished, !stopped else { return }
        finished = true; stop(); completion(result)
    }
    func stop() { stopped = true; queue.async { [capture] in if capture.isRunning { capture.stopRunning() } } }
}

import SwiftUI
import UniformTypeIdentifiers

@main
struct UniPassApp: App {
    @StateObject private var store = VaultStore()
    @StateObject private var sync = SyncCoordinator()

    init() {
        CustomFont.configureAppearance(category: UIApplication.shared.preferredContentSizeCategory)
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .environmentObject(sync)
                .customFont()
                .onReceive(NotificationCenter.default.publisher(for: UIContentSizeCategory.didChangeNotification)) { _ in
                    CustomFont.configureAppearance(category: UIApplication.shared.preferredContentSizeCategory)
                }
                .tint(Color(red: 0.05, green: 0.48, blue: 0.48))
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var store: VaultStore
    @EnvironmentObject private var sync: SyncCoordinator
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("autoLockSeconds") private var autoLockSeconds = 0
    @State private var backgroundAt: Date?
    @State private var lockTask: Task<Void, Never>?
    @State private var sessionID = UUID()

    var body: some View {
        ZStack {
            if store.isUnlocked {
                TabView {
                    VaultHomeView()
                        .tabItem { Label("Vault", systemImage: "key.fill") }
                    GeneratorView()
                        .tabItem { Label("Generator", systemImage: "wand.and.stars") }
                    SettingsView()
                        .tabItem { Label("Settings", systemImage: "gearshape.fill") }
                }
                .id(sessionID)
                .safeAreaInset(edge: .top) {
                    if let warning = store.externalChangeMessage {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("External file change detected", systemImage: "exclamationmark.triangle.fill").customFont(.headline)
                            Text(warning).customFont(.footnote)
                            Button("Lock and reload vault") { store.lock() }.buttonStyle(.bordered)
                        }.padding().frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.orange.opacity(0.15))
                    }
                }
            } else {
                UnlockView()
            }
            if scenePhase != .active {
                Color(uiColor: .systemGroupedBackground).ignoresSafeArea()
                VStack(spacing: 18) {
                    Image(systemName: "lock.shield.fill").font(CustomFont.symbol(size: 58)).foregroundStyle(.tint)
                    Text("uniPass").customFont(.title)
                    Text("Vault contents are hidden").foregroundStyle(.secondary)
                }
            }
        }
        .alert("Operation incomplete", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
            Button("OK", role: .cancel) { store.errorMessage = nil }
        } message: { Text(store.errorMessage ?? "") }
        .onChange(of: store.isUnlocked) { unlocked in
            if unlocked {
                sessionID = UUID()
                sync.loadConfiguration(vaultURL: store.vaultURL)
            } else {
                sync.cancelPending()
            }
        }
        .onChange(of: store.vaultURL) { _ in sync.cancelPending() }
        .onReceive(Timer.publish(every: 5, on: .main, in: .common).autoconnect()) { _ in
            if scenePhase == .active { Task { await store.checkForExternalChanges() } }
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .background:
                beginBackgroundLock()
            case .inactive:
                #if targetEnvironment(macCatalyst)
                // A Mac app may become inactive without receiving .background.
                if store.isUnlocked { beginBackgroundLock() }
                #endif
            case .active:
                lockTask?.cancel()
                if let backgroundAt, Date().timeIntervalSince(backgroundAt) >= Double(autoLockSeconds) {
                    store.lock()
                }
                backgroundAt = nil
                Task { await store.checkForExternalChanges() }
            default: break
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)) { _ in
            store.lock()
        }
    }

    private func beginBackgroundLock() {
        guard backgroundAt == nil else { return }
        backgroundAt = Date()
        lockTask?.cancel()
        if autoLockSeconds <= 0 {
            store.lock()
        } else {
            let seconds = min(autoLockSeconds, 300)
            lockTask = Task { @MainActor in
                do { try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000) }
                catch { return }
                guard !Task.isCancelled else { return }
                store.lock()
            }
        }
    }
}

struct UnlockView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var password = ""
    @State private var confirmation = ""
    @State private var busy = false
    @State private var error: String?
    @State private var choosingBackup = false
    @State private var choosingLocation = false
    @State private var backup: Data?
    @FocusState private var passwordFocused: Bool

    var body: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(spacing: 26) {
                    Spacer(minLength: 30)
                    Image(systemName: "lock.fill")
                        .font(CustomFont.symbol(size: 42, weight: .medium)).foregroundStyle(.white)
                        .frame(width: 96, height: 96)
                        .background(Color.accentColor.gradient, in: RoundedRectangle(cornerRadius: 27))
                    VStack(spacing: 8) {
                        Text("uniPass").customFont(.largeTitle)
                        Text(store.hasVault ? "Your passwords belong only to you" : (backup == nil ? "Create your private vault" : "Restore from an encrypted backup"))
                            .foregroundStyle(.secondary)
                    }
                    VStack(spacing: 16) {
                        SecureField(backup != nil ? "Backup master password" : "Master password", text: $password)
                            .textContentType(store.hasVault ? .password : .newPassword)
                            .focused($passwordFocused)
                            .submitLabel(.go).onSubmit { authenticate() }
                            .padding().background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))
                        if !store.hasVault && backup == nil {
                            SecureField("Confirm master password (at least 12 characters)", text: $confirmation)
                                .textContentType(.newPassword)
                                .padding().background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))
                        }
                        if let error { Text(error).customFont(.footnote).foregroundStyle(.red).frame(maxWidth: .infinity, alignment: .leading) }
                        Button(action: authenticate) {
                            HStack {
                                if busy { ProgressView().tint(.white) }
                                Text(store.hasVault ? "Unlock" : (backup == nil ? "Create vault" : "Verify and restore"))
                                    .customFont(.headline)
                            }
                            .frame(maxWidth: .infinity).padding(.vertical, 14)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(busy || password.isEmpty)
                        if store.biometricEnabled && store.hasVault {
                            Button {
                                busy = true
                                Task { @MainActor in
                                    defer { busy = false }
                                    do { try await store.unlockWithBiometrics() }
                                    catch { self.error = error.localizedDescription }
                                }
                            } label: { Label("Use Face ID / Touch ID", systemImage: "faceid").padding(.top, 10) }
                            .disabled(busy)
                        }
                        if !store.hasVault {
                            Button(backup == nil ? "Restore encrypted backup…" : "Cancel restore and create a new vault") {
                                if backup == nil { choosingBackup = true } else { backup = nil; password = "" }
                            }
                            .disabled(busy)
                        }
                    }
                    Button("Open another vault / choose location…") { choosingLocation = true }.disabled(busy)
                    if let locationError = store.locationError {
                        Text(locationError).customFont(.footnote).foregroundStyle(.red)
                    }
                    Text(store.vaultURL.path).customFont(.caption2).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center).lineLimit(3)
                    if !store.hasVault {
                        Text("No account and no password recovery. Keep your master password safe.\nHave a WebDAV / S3 vault? Create an empty vault with the same master password,\nthen configure synchronization in Settings.")
                            .customFont(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    } else {
                        Label("Local encryption · no account · no tracking", systemImage: "checkmark.shield")
                            .customFont(.footnote).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 30)
                }
                .padding(28).frame(maxWidth: 450)
                .frame(maxWidth: .infinity, minHeight: geometry.size.height)
            }
            .background(Color(uiColor: .systemGroupedBackground).ignoresSafeArea())
        }
        .sheet(isPresented: $choosingLocation) {
            NavigationStack {
                VaultLocationView()
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { choosingLocation = false } } }
            }
        }
        .onChange(of: store.vaultURL) { _ in choosingLocation = false; password = ""; confirmation = ""; backup = nil }
        .fileImporter(isPresented: $choosingBackup, allowedContentTypes: [.data, .json]) { result in
            do {
                let url = try result.get()
                let data = try BackupFiles.readScoped(url, maximumBytes: VaultBackup.maximumBytes)
                try VaultBackup.validate(data)
                backup = data; password = ""; confirmation = ""; error = nil
            } catch { self.error = error.localizedDescription }
        }
    }

    private func authenticate() {
        guard !busy else { return }
        error = nil
        if !store.hasVault && backup == nil {
            guard password.count >= 12 else { error = "Use a master password with at least 12 characters; a long passphrase is recommended."; return }
            guard password == confirmation else { error = "The master password confirmation does not match."; return }
        }
        passwordFocused = false
        busy = true
        Task { @MainActor in
            defer { busy = false }
            do {
                if store.hasVault { try await store.unlock(password: password) }
                else if let backup { try await store.restoreBackup(data: backup, password: password) }
                else { try await store.create(password: password) }
                password = ""; confirmation = ""; backup = nil
            } catch { self.error = error.localizedDescription }
        }
    }
}

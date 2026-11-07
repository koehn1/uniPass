import SwiftUI

struct VaultHomeView: View {
    @EnvironmentObject private var store: VaultStore
    @State private var search = ""
    @State private var newEntry: VaultEntry?
    @State private var folderPrompt = false
    @State private var folderName = ""
    @State private var editingFolder: VaultFolder?
    @State private var deletingFolder: VaultFolder?

    private var active: [VaultEntry] { store.payload.entries.filter { $0.deletedAt == nil } }
    private var results: [VaultEntry] { active.filter { $0.matches(search) } }

    var body: some View {
        NavigationStack {
            List {
                if search.isEmpty {
                    CustomSection {
                        route("All entries", icon: "key.fill", color: .accentColor, filter: .all, count: active.count)
                        route("Favorites", icon: "star.fill", color: .orange, filter: .favorites, count: active.filter(\.favorite).count)
                        route("Recently Deleted", icon: "trash.fill", color: .gray, filter: .trash, count: store.payload.entries.filter { $0.deletedAt != nil }.count)
                    }
                    CustomSection {
                        ForEach(store.payload.folders) { folder in
                            route(folder.name, icon: "folder.fill", color: .accentColor, filter: .folder(folder.id), count: active.filter { $0.folderID == folder.id }.count)
                                .contextMenu {
                                  if store.canEdit {
                                    Button("Rename", systemImage: "pencil") {
                                        editingFolder = folder; folderName = folder.name; folderPrompt = true
                                    }
                                    Button("Delete folder", systemImage: "trash", role: .destructive) { deletingFolder = folder }
                                  }
                                }
                        }
                        route("Uncategorized", icon: "folder", color: .gray, filter: .uncategorized, count: active.filter { $0.folderID == nil }.count)
                        if store.canEdit {
                            Button {
                                editingFolder = nil; folderName = ""; folderPrompt = true
                            } label: { Label("New folder", systemImage: "folder.badge.plus") }
                        }
                    } header: { Text("Folders") } footer: { Text("Press and hold a folder to rename or delete it. Deleting a folder does not delete its entries.") }
                    CustomSection("Recently modified") {
                        if active.isEmpty {
                            VStack(alignment: .leading, spacing: 10) {
                                Label("This is your private vault", systemImage: "lock.shield")
                                    .customFont(.headline)
                                Text(store.canEdit ? "Tap the plus button to add an account, or import Bitwarden JSON from Settings." : "This mobile device is currently read-only. Enable Allow Mobile Editing in Security settings.")
                                    .customFont(.subheadline).foregroundStyle(.secondary)
                            }.padding(.vertical, 12)
                        }
                        ForEach(active.sorted { $0.modifiedAt > $1.modifiedAt }.prefix(5)) { entry in
                            NavigationLink { EntryDetailView(entryID: entry.id) } label: { EntryRow(entry: entry) }
                        }
                    }
                } else {
                    CustomSection("Search results · \(results.count)") {
                        ForEach(results) { entry in
                            NavigationLink { EntryDetailView(entryID: entry.id) } label: { EntryRow(entry: entry) }
                        }
                        if results.isEmpty { Text("No matching entries").foregroundStyle(.secondary) }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Vault")
            .searchable(text: $search, prompt: "Search names, websites, and usernames")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { store.lock() } label: { Image(systemName: "lock") }.accessibilityLabel("Lock vault")
                }
                if store.canEdit {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button { newEntry = VaultEntry() } label: { Image(systemName: "plus") }.accessibilityLabel("New entry")
                    }
                }
            }
            .sheet(item: $newEntry) { EntryEditorView(entry: $0, isNew: true) }
            .alert(editingFolder == nil ? "New folder" : "Rename folder", isPresented: $folderPrompt) {
                TextField("Name", text: $folderName)
                Button("Cancel", role: .cancel) { }
                Button("Save") {
                    do {
                        if let folder = editingFolder { try store.renameFolder(id: folder.id, name: folderName) }
                        else { try store.addFolder(name: folderName) }
                    } catch { store.errorMessage = error.localizedDescription }
                }
            }
            .confirmationDialog("Delete folder? Its entries will move to Uncategorized.", isPresented: Binding(get: { deletingFolder != nil }, set: { if !$0 { deletingFolder = nil } }), titleVisibility: .visible) {
                Button("Delete folder", role: .destructive) {
                    guard let folder = deletingFolder else { return }
                    do { try store.deleteFolder(id: folder.id) }
                    catch { store.errorMessage = error.localizedDescription }
                    deletingFolder = nil
                }
            }
        }
    }

    private func route(_ title: String, icon: String, color: Color, filter: EntryFilter, count: Int) -> some View {
        NavigationLink { EntryListView(title: title, filter: filter) } label: {
            HStack(spacing: 12) {
                Image(systemName: icon).font(CustomFont.symbol(size: 16, weight: .medium))
                    .foregroundStyle(.white).frame(width: 30, height: 30)
                    .background(color, in: RoundedRectangle(cornerRadius: 7))
                Text(title)
                Spacer()
                Text("\(count)").foregroundStyle(.secondary)
            }
            .padding(.vertical, 2)
        }
    }
}

enum EntryFilter {
    case all, favorites, trash, uncategorized, folder(UUID)
    func includes(_ entry: VaultEntry) -> Bool {
        if case .trash = self { return entry.deletedAt != nil }
        guard entry.deletedAt == nil else { return false }
        switch self {
        case .all: return true
        case .favorites: return entry.favorite
        case .uncategorized: return entry.folderID == nil
        case .folder(let id): return entry.folderID == id
        case .trash: return false
        }
    }
    var isTrash: Bool { if case .trash = self { return true }; return false }
    var folderID: UUID? { if case .folder(let id) = self { return id }; return nil }
}

struct EntryListView: View {
    @EnvironmentObject private var store: VaultStore
    let title: String
    let filter: EntryFilter
    @State private var search = ""
    @State private var quickFilter = "All"
    @State private var newEntry: VaultEntry?
    @State private var permanentDelete: VaultEntry?
    @State private var copied = false
    @AppStorage("clipboardSeconds") private var clipboardSeconds = 30

    private var entries: [VaultEntry] {
        let filtered = store.payload.entries.filter { entry in
            filter.includes(entry) && entry.matches(search)
                && (quickFilter != "Has 2FA" || !entry.totp.isEmpty)
                && (quickFilter != "Weak passwords" || (!entry.password.isEmpty && PasswordGenerator.strength(entry.password).score < 0.3))
        }
        if quickFilter == "Recently modified" { return filtered.sorted { $0.modifiedAt > $1.modifiedAt } }
        return filtered.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    var body: some View {
        List {
            if !filter.isTrash {
                CustomSection {
                    Picker("Filter", selection: $quickFilter) {
                        ForEach(["All", "Has 2FA", "Weak passwords", "Recently modified"], id: \.self) { Text($0) }
                    }.pickerStyle(.segmented)
                }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
            }
            CustomSection {
                ForEach(entries) { entry in
                    NavigationLink { EntryDetailView(entryID: entry.id) } label: { EntryRow(entry: entry) }
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            if filter.isTrash && store.canEdit {
                                Button("Delete permanently", role: .destructive) { permanentDelete = entry }
                            } else if !filter.isTrash {
                                Button { SecureClipboard.copy(entry.password, clearAfter: Double(clipboardSeconds)); copied = true }
                                label: { Label("Copy password", systemImage: "doc.on.doc") }.tint(.accentColor)
                                if store.canEdit {
                                    Button("Delete", role: .destructive) { perform { try store.trash(id: entry.id) } }
                                }
                            }
                        }
                        .swipeActions(edge: .leading) {
                          if store.canEdit {
                            if filter.isTrash {
                                Button("Restore") { perform { try store.restore(id: entry.id) } }.tint(.green)
                            } else {
                                Button {
                                    var updated = entry; updated.favorite.toggle()
                                    perform { try store.save(updated) }
                                } label: { Label(entry.favorite ? "Remove favorite" : "Favorite", systemImage: "star") }.tint(.orange)
                            }
                          }
                        }
                }
                if entries.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: filter.isTrash ? "trash" : "key").font(CustomFont.symbol(size: 34))
                        Text(search.isEmpty ? "No entries" : "No search results")
                    }.foregroundStyle(.secondary).frame(maxWidth: .infinity).padding(32)
                }
            } footer: {
                Text(filter.isTrash ? "\(entries.count) entries · Not cleared automatically; permanent deletion requires confirmation" : "\(entries.count) entries · Swipe right to copy; swipe left to favorite")
            }
        }
        .listStyle(.insetGrouped).navigationTitle(title)
        .searchable(text: $search, prompt: "Search names, websites, and usernames")
        .toolbar {
            if !filter.isTrash && store.canEdit {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { newEntry = VaultEntry(folderID: filter.folderID) } label: { Image(systemName: "plus") }
                }
            }
        }
        .sheet(item: $newEntry) { EntryEditorView(entry: $0, isNew: true) }
        .alert("Password copied", isPresented: $copied) { Button("OK", role: .cancel) { } }
        message: { Text("The clipboard will expire in \(clipboardSeconds) seconds and is available only on this device.") }
        .confirmationDialog("Permanent deletion cannot be undone", isPresented: Binding(get: { permanentDelete != nil }, set: { if !$0 { permanentDelete = nil } }), titleVisibility: .visible) {
            Button("Delete permanently", role: .destructive) {
                if let entry = permanentDelete { perform { try store.permanentlyDelete(id: entry.id) } }
                permanentDelete = nil
            }
        }
    }

    private func perform(_ action: () throws -> Void) {
        do { try action() } catch { store.errorMessage = error.localizedDescription }
    }
}

struct EntryRow: View {
    let entry: VaultEntry
    var body: some View {
        HStack(spacing: 12) {
            SiteIcon(name: entry.name)
            VStack(alignment: .leading, spacing: 4) {
                Text(entry.name.isEmpty ? "Untitled" : entry.name).customFont(.body).lineLimit(1)
                Text(entry.username.isEmpty ? (entry.urls.first ?? "No username") : entry.username)
                    .customFont(.subheadline).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
            if entry.favorite { Image(systemName: "star.fill").font(CustomFont.symbol(size: 12)).foregroundStyle(.orange) }
            if !entry.totp.isEmpty {
                Text("2FA").customFont(.caption2).foregroundStyle(.tint)
                    .padding(5).background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 5))
            }
        }.padding(.vertical, 5)
    }
}

struct SiteIcon: View {
    let name: String
    var size: CGFloat = 42
    private var color: Color {
        let colors: [Color] = [.teal, .indigo, .orange, .blue, .pink, .purple]
        let index = name.unicodeScalars.reduce(0) { ($0 + Int($1.value)) % colors.count }
        return colors[index]
    }
    var body: some View {
        Text(String(name.prefix(1)).uppercased()).customFont(size: size * 0.43)
            .foregroundStyle(.white).frame(width: size, height: size)
            .background(color.gradient, in: RoundedRectangle(cornerRadius: size * 0.24))
            .accessibilityHidden(true)
    }
}

extension VaultEntry {
    func matches(_ query: String) -> Bool {
        let query = query.trimmingCharacters(in: .whitespacesAndNewlines)
        return query.isEmpty || ([name, username] + urls).contains { $0.localizedStandardContains(query) }
    }
}

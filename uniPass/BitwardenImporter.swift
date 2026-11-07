import Foundation
import CryptoKit

struct BitwardenImportPreview {
    let itemCount: Int
    let folderCount: Int
    let otherTypeCount: Int
}

enum BitwardenImporter {
    private struct Export {
        let items: [[String: Any]]
        let folders: [[String: Any]]
    }

    static func preview(data: Data) throws -> BitwardenImportPreview {
        let export = try parse(data)
        return BitwardenImportPreview(itemCount: export.items.count,
            folderCount: export.folders.count,
            otherTypeCount: export.items.filter { integer($0["type"]) != 1 }.count)
    }

    /// Only identical original JSON is deduplicated. An edited version of the
    /// same source ID is kept separately, including when the previous entry is trashed.
    struct AttachmentSource {
        let entryID: UUID
        let url: URL
        let fileName: String
    }

    /// Do not include item names, filenames or imported values in error messages.
    enum AttachmentImportError: LocalizedError, Equatable {
        case directoryRequired, exportChanged, invalidMetadata, missingFiles
        case unsupportedLayout, unmappedDirectory, ambiguousDirectory, filesMismatch

        var errorDescription: String? {
            switch self {
            case .directoryRequired:
                return "The JSON references attachments, but no export directory was selected. Choose the folder above both data.json and attachments; no data was imported."
            case .exportChanged:
                return "The selected directory is missing data.json or it changed since preview. Select the export root containing data.json and attachments again; no data was imported."
            case .invalidMetadata:
                return "The attachment metadata format in the JSON is unsupported. Export a new Bitwarden ZIP containing attachments; no data was imported."
            case .missingFiles:
                return "The JSON references attachments, but the corresponding directory or file is missing. Fully extract the ZIP without moving data.json separately; no data was imported."
            case .unsupportedLayout:
                return "The attachments root contains a non-directory file. It should contain only entry folders; use the complete, unmodified ZIP extraction; no data was imported."
            case .unmappedDirectory:
                return "An attachment directory cannot be matched to a data.json entry. Confirm that JSON and attachments came from the same complete export and were not renamed; no data was imported."
            case .ambiguousDirectory:
                return "An attachment directory may match multiple entries because of duplicate names or naming collisions. Give the affected Bitwarden entries unique names and export again; no data was imported."
            case .filesMismatch:
                return "The attachment file list does not match the JSON metadata. Missing files, extra files, or unsupported names may be present; no data was imported."
            }
        }
    }

    static func importVault(data: Data, into existing: VaultPayload, attachmentsDirectory: URL? = nil) throws
        -> (payload: VaultPayload, importedCount: Int, attachmentSources: [AttachmentSource]) {
        let export = try parse(data)
        let files = try attachmentFiles(export: export, data: data, directory: attachmentsDirectory)
        var attachmentSources: [AttachmentSource] = []
        var result = existing
        var folderMap: [String: UUID] = [:]
        var usedFolderIDs = Set(result.folders.map(\.id))
        for folder in export.folders {
            guard let sourceID = folder["id"] as? String, !sourceID.isEmpty else {
                throw VaultError.invalidImport
            }
            let name = text(folder["name"])
            let preferredID = stableID(sourceID, namespace: "folder")
            if let match = result.folders.first(where: { $0.id == preferredID && $0.name == name })
                ?? result.folders.first(where: { $0.name == name }) {
                folderMap[sourceID] = match.id
            } else {
                let id = usedFolderIDs.contains(preferredID) ? UUID() : preferredID
                result.folders.append(VaultFolder(id: id, name: name))
                usedFolderIDs.insert(id)
                folderMap[sourceID] = id
            }
        }

        var originals: [String: UUID] = [:]
        for entry in existing.entries {
            if let raw = entry.originalJSON, let bytes = raw.data(using: .utf8),
               let object = try? JSONSerialization.jsonObject(with: bytes),
               let canonical = try? jsonString(object) {
                if originals[canonical] == nil { originals[canonical] = entry.id }
            }
        }
        var usedEntryIDs = Set(result.entries.map(\.id))
        var count = 0
        let now = Date()
        for (itemIndex, item) in export.items.enumerated() {
            let original = try jsonString(item)
            if let existingID = originals[original] {
                attachmentSources += (files[itemIndex] ?? []).map {
                    AttachmentSource(entryID: existingID, url: $0, fileName: $0.lastPathComponent)
                }
                continue
            }
            let sourceID = text(item["id"])
            let preferredID = sourceID.isEmpty ? UUID() : stableID(sourceID, namespace: "item")
            let id = usedEntryIDs.contains(preferredID) ? UUID() : preferredID
            let login = item["login"] as? [String: Any] ?? [:]
            let type = integer(item["type"])
            var notes = text(item["notes"])
            if type != 1 {
                let kind: String
                switch type {
                case 2: kind = "Secure note"
                case 3: kind = "Card"
                case 4: kind = "Identity"
                default: kind = "Other type \(type)"
                }
                // Keep non-login data visible as well as losslessly recoverable.
                notes += (notes.isEmpty ? "" : "\n\n") + "[Bitwarden \(kind)]\n" + original
            }
            let fields = (item["fields"] as? [[String: Any]] ?? []).map { field in
                let rawType = integer(field["type"])
                var value = fieldText(field["value"])
                if rawType == 3, field["value"] == nil || field["value"] is NSNull {
                    value = fieldText(field["linkedId"])
                }
                return CustomField(name: text(field["name"]), value: value,
                                   type: (0...3).contains(rawType) ? rawType : 0)
            }
            let urls = (login["uris"] as? [[String: Any]] ?? []).compactMap { $0["uri"] as? String }
            let entry = VaultEntry(id: id, name: text(item["name"]),
                username: text(login["username"]), password: text(login["password"]),
                urls: urls, totp: text(login["totp"]), notes: notes,
                folderID: (item["folderId"] as? String).flatMap { folderMap[$0] },
                favorite: item["favorite"] as? Bool ?? false, fields: fields,
                originalJSON: original, createdAt: date(item["creationDate"]) ?? now,
                modifiedAt: date(item["revisionDate"]) ?? now,
                deletedAt: date(item["deletedDate"]))
            result.entries.append(entry)
            usedEntryIDs.insert(id)
            originals[original] = id
            attachmentSources += (files[itemIndex] ?? []).map {
                AttachmentSource(entryID: id, url: $0, fileName: $0.lastPathComponent)
            }
            count += 1
        }
        try VaultCrypto.validatePayload(result)
        return (result, count, attachmentSources)
    }

    /// ZIP exports do not necessarily list attachment metadata in data.json.
    /// Inventory the actual files; never interpret an unmatched directory as empty.
    /// Legacy: attachments/{cipher.id}/{original filename} (clients PR #10465).
    /// Modern: attachments/{sanitized cipher.name}[_{n}]/{sanitized stem}[_{n}]{extension}
    /// (PR #21596; individual-vault-export.service.ts, checked at 5a03a6765a3a).
    /// Cipher sanitization replaces / \\ > < : " | ? * with _, then collapses __+.
    /// Its suffix counter is keyed by ORIGINAL names and only counts ciphers with
    /// attachments; data.json need not include that membership or its ordering.
    /// Check ambiguity per directory, including possible exporter-generated suffixes.
    /// Unrelated duplicate names must not block a uniquely mapped directory; actual
    /// duplicate/colliding names are not guessed. Legacy ID mapping still works.
    /// Files retain their actual exported names, including filename suffixes.
    private static func attachmentFiles(export: Export, data: Data, directory: URL?) throws -> [Int: [URL]] {
        var metadata: [Int: [String]] = [:]
        for (index, item) in export.items.enumerated() {
            if let value = item["attachments"], !(value is NSNull) {
                guard let attachments = value as? [[String: Any]] else { throw AttachmentImportError.invalidMetadata }
                metadata[index] = try attachments.map {
                    guard let name = $0["fileName"] as? String,
                          VaultCrypto.validAttachmentFileName(name) else { throw VaultError.unsafeAttachmentPath }
                    return name
                }
            }
        }
        guard let directory else {
            guard metadata.values.allSatisfy({ $0.isEmpty }) else { throw AttachmentImportError.directoryRequired }
            return [:]
        }
        let root = try VaultAttachmentDisk.children(directory)
        guard root.contains(where: { $0.name == "data.json" && !$0.isDirectory }),
              try VaultAttachmentDisk.read(directory.appendingPathComponent("data.json"),
                  maximum: VaultCrypto.maximumPlaintextBytes) == data else { throw AttachmentImportError.exportChanged }
        guard let attachmentRoot = root.first(where: { $0.name == "attachments" }) else {
            guard metadata.values.allSatisfy({ $0.isEmpty }) else { throw AttachmentImportError.missingFiles }
            return [:]
        }
        guard attachmentRoot.isDirectory else { throw VaultError.unsafeAttachmentPath }
        let base = directory.appendingPathComponent("attachments", isDirectory: true)
        var ids: [String: [Int]] = [:]
        var names: [String: [Int]] = [:]
        let originalNameCounts = export.items.reduce(into: [String: Int]()) { counts, item in
            counts[text(item["name"]), default: 0] += 1
        }
        for (index, item) in export.items.enumerated() {
            if let id = item["id"] as? String, !id.isEmpty {
                try VaultAttachmentDisk.component(id)
                ids[id, default: []].append(index)
            }
            let name = sanitized(text(item["name"]))
            if VaultCrypto.validAttachmentFileName(name) { names[name, default: []].append(index) }
        }
        var result: [Int: [URL]] = [:]
        var total: Int64 = 0
        var count = 0
        for folder in try VaultAttachmentDisk.children(base) {
            // Finder creates this hidden file alongside the cipher directories.
            // Only ignore a regular root-level file: children() has already
            // rejected symlinks, and actual per-entry attachments keep all names.
            if folder.name == ".DS_Store", !folder.isDirectory { continue }
            guard folder.isDirectory else { throw AttachmentImportError.unsupportedLayout }
            var candidates = Set((ids[folder.name] ?? []) + (names[folder.name] ?? []))
            // A literal Example_1 can also be the second attachment-bearing
            // Example. JSON need not record which entries have attachments or
            // their export order, so include every possible original owner.
            // Resolve only this suffix instead of expanding a quadratic alias map.
            if let separator = folder.name.lastIndex(of: "_") {
                let suffix = String(folder.name[folder.name.index(after: separator)...])
                if let number = Int(suffix), number > 0, String(number) == suffix {
                    let baseName = String(folder.name[..<separator])
                    for index in names[baseName] ?? [] {
                        let originalName = text(export.items[index]["name"])
                        if originalNameCounts[originalName, default: 0] > number {
                            candidates.insert(index)
                        }
                    }
                }
            }
            guard !candidates.isEmpty else { throw AttachmentImportError.unmappedDirectory }
            guard candidates.count == 1, let index = candidates.first, result[index] == nil else {
                throw AttachmentImportError.ambiguousDirectory
            }
            let folderURL = base.appendingPathComponent(folder.name, isDirectory: true)
            let children = try VaultAttachmentDisk.children(folderURL)
            for child in children {
                guard !child.isDirectory else { throw VaultError.unsafeAttachmentPath }
                guard child.size >= 0, child.size <= VaultCrypto.maximumAttachmentBytes else { throw VaultError.dataTooLarge }
                total += child.size
                count += 1
                guard total <= VaultCrypto.maximumAttachmentImportBytes,
                      count <= VaultCrypto.maximumAttachmentCount else { throw VaultError.dataTooLarge }
            }
            let actual = Set(children.map(\.name))
            if let expected = metadata[index], !expected.isEmpty {
                let legacy = Set(expected)
                var occurrences: [String: Int] = [:]
                let modern = Set(expected.map { name -> String in
                    // Match the official exporter, including its unusual removal
                    // of ALL stem dots: report.v1.txt becomes reportv1.txt. Its
                    // filename counter is keyed by the sanitized name + extension;
                    // e.g. a:b.txt, a?b.txt become a_b.txt, a_b_1.txt.
                    let parts = name.components(separatedBy: ".")
                    let suffix = parts.count > 1 ? "." + parts.last! : ""
                    let stem = sanitized(parts.count > 1 ? parts.dropLast().joined() : name)
                    let full = stem + suffix
                    let number = occurrences[full, default: 0]
                    occurrences[full] = number + 1
                    return stem + (number == 0 ? "" : "_\(number)") + suffix
                })
                let matchesLegacy = actual == legacy && legacy.count == expected.count
                let matchesModern = actual == modern && modern.count == expected.count
                guard matchesLegacy || matchesModern else {
                    throw AttachmentImportError.filesMismatch
                }
            }
            result[index] = children.map { folderURL.appendingPathComponent($0.name) }
        }
        for (index, expected) in metadata where !expected.isEmpty {
            guard result[index]?.isEmpty == false else { throw AttachmentImportError.missingFiles }
        }
        return result
    }

    private static func sanitized(_ name: String) -> String {
        name.replacingOccurrences(of: #"[/\\><:"|?*]"#, with: "_", options: .regularExpression)
            .replacingOccurrences(of: "__+", with: "_", options: .regularExpression)
    }

    private static func parse(_ data: Data) throws -> Export {
        guard data.count <= VaultCrypto.maximumPlaintextBytes else { throw VaultError.dataTooLarge }
        let object: Any
        do { object = try JSONSerialization.jsonObject(with: data) }
        catch { throw VaultError.invalidImport }
        guard let root = object as? [String: Any] else { throw VaultError.invalidImport }
        // Fail closed for wrappers, malformed flags and password-protected formats.
        for flag in ["encrypted", "passwordProtected"] {
            if let value = root[flag], !(value is NSNull) {
                guard let number = value as? NSNumber,
                      CFGetTypeID(number) == CFBooleanGetTypeID(), !number.boolValue else {
                    throw VaultError.encryptedImport
                }
            }
        }
        if root["encKeyValidation_DO_NOT_EDIT"] != nil || root["salt"] != nil
            || root["data"] != nil { throw VaultError.encryptedImport }
        guard let items = root["items"] as? [[String: Any]] else { throw VaultError.invalidImport }
        let folders: [[String: Any]]
        if let value = root["folders"], !(value is NSNull) {
            guard let parsed = value as? [[String: Any]] else { throw VaultError.invalidImport }
            folders = parsed
        } else { folders = [] }
        for item in items {
            guard item["name"] is String, let type = item["type"] as? NSNumber,
                  CFGetTypeID(type) != CFBooleanGetTypeID(), type.intValue >= 1,
                  type.doubleValue == Double(type.intValue) else { throw VaultError.invalidImport }
            if type.intValue == 1, !(item["login"] is [String: Any]) {
                throw VaultError.invalidImport
            }
        }
        var folderIDs = Set<String>()
        for folder in folders {
            guard let id = folder["id"] as? String, !id.isEmpty,
                  folder["name"] is String, folderIDs.insert(id).inserted else {
                throw VaultError.invalidImport
            }
        }
        return Export(items: items, folders: folders)
    }

    private static func text(_ value: Any?) -> String { value as? String ?? "" }

    private static func integer(_ value: Any?) -> Int { (value as? NSNumber)?.intValue ?? 0 }

    private static func fieldText(_ value: Any?) -> String {
        if let string = value as? String { return string }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
            return number.stringValue
        }
        return ""
    }

    private static func jsonString(_ object: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .fragmentsAllowed])
        guard let string = String(data: data, encoding: .utf8) else { throw VaultError.invalidImport }
        return string
    }

    private static func date(_ value: Any?) -> Date? {
        guard let value = value as? String else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }

    private static func stableID(_ source: String, namespace: String) -> UUID {
        if let id = UUID(uuidString: source) { return id }
        var bytes = Array(SHA256.hash(data: Data("uniPass.bitwarden.\(namespace):\(source)".utf8)).prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | 0x80
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

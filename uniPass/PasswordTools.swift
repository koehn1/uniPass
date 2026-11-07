import Foundation
import Security
import CryptoKit
import UIKit
import UniformTypeIdentifiers

enum PasswordGeneratorError: LocalizedError {
    case noCharacterGroups
    case invalidLength
    case lengthTooShort
    case randomFailure

    var errorDescription: String? {
        switch self {
        case .noCharacterGroups: return "Select at least one password character group."
        case .invalidLength: return "Password length must be between 1 and 4096."
        case .lengthTooShort: return "Password length cannot be shorter than the number of selected character groups."
        case .randomFailure: return "The system secure random generator failed. Try again."
        }
    }
}

enum PasswordGenerator {
    static func generate(length: Int, uppercase: Bool = true, lowercase: Bool = true,
                         digits: Bool = true, symbols: Bool = true) throws -> String {
        guard (1...4096).contains(length) else { throw PasswordGeneratorError.invalidLength }
        var groups: [[Character]] = []
        if uppercase { groups.append(Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) }
        if lowercase { groups.append(Array("abcdefghijklmnopqrstuvwxyz")) }
        if digits { groups.append(Array("0123456789")) }
        if symbols { groups.append(Array("!@#$%^&*()-_=+[]{};:,.<>?/\\|~`\"'")) }
        guard !groups.isEmpty else { throw PasswordGeneratorError.noCharacterGroups }
        guard length >= groups.count else { throw PasswordGeneratorError.lengthTooShort }

        let alphabet = groups.flatMap { $0 }
        var result: [Character] = []
        result.reserveCapacity(length)
        for group in groups { result.append(group[try randomIndex(upperBound: group.count)]) }
        while result.count < length {
            result.append(alphabet[try randomIndex(upperBound: alphabet.count)])
        }
        // Shuffle the mandatory characters as well, so their positions are not predictable.
        if result.count > 1 {
            for index in stride(from: result.count - 1, through: 1, by: -1) {
                result.swapAt(index, try randomIndex(upperBound: index + 1))
            }
        }
        return String(result)
    }

    private static func randomIndex(upperBound: Int) throws -> Int {
        let bound = UInt32(upperBound)
        let threshold = (0 &- bound) % bound
        while true {
            var value: UInt32 = 0
            let status = withUnsafeMutableBytes(of: &value) { bytes -> OSStatus in
                guard let address = bytes.baseAddress else { return errSecParam }
                return SecRandomCopyBytes(kSecRandomDefault, bytes.count, address)
            }
            guard status == errSecSuccess else { throw PasswordGeneratorError.randomFailure }
            if value >= threshold { return Int(value % bound) }
        }
    }

    /// A conservative local heuristic, not a breach check or a guarantee of entropy.
    /// Score is normalized to 0...1.
    static func strength(_ password: String) -> (label: String, score: Double) {
        guard !password.isEmpty else { return ("Not set", 0) }
        let characters = Array(password.prefix(256))
        let sample = String(characters)
        var alphabetSize = 0.0
        if sample.rangeOfCharacter(from: .lowercaseLetters) != nil { alphabetSize += 26 }
        if sample.rangeOfCharacter(from: .uppercaseLetters) != nil { alphabetSize += 26 }
        if sample.rangeOfCharacter(from: .decimalDigits) != nil { alphabetSize += 10 }
        if sample.rangeOfCharacter(from: .punctuationCharacters.union(.symbols)) != nil { alphabetSize += 32 }
        if sample.rangeOfCharacter(from: .whitespacesAndNewlines) != nil { alphabetSize += 1 }
        if sample.unicodeScalars.contains(where: { !$0.isASCII }) { alphabetSize += 100 }
        let length = Double(characters.count)
        let unique = Double(Set(characters).count)
        let diversity = min(1, unique / max(1, min(length, 12)))
        var score = min(1, length * log2(max(2, alphabetSize)) / 100)
        score *= diversity
        score = min(score, length / 16)
        let lower = sample.lowercased()
        let common = ["password", "qwerty", "123456", "654321", "abcdef", "letmein", "admin", "welcome", "iloveyou"]
        if common.contains(where: { lower.contains($0) }) { score *= 0.35 }
        // Penalize short repeated units such as ababab or 123123, regardless of length.
        if characters.count >= 4 {
            for size in 1...min(8, characters.count / 2) {
                if characters.indices.allSatisfy({ characters[$0] == characters[$0 % size] }) {
                    score = min(score, 0.15)
                    break
                }
            }
        }
        score = max(0, min(1, score))
        switch score {
        case ..<0.3: return ("Weak", score)
        case ..<0.6: return ("Fair", score)
        case ..<0.8: return ("Strong", score)
        default: return ("Very strong", score)
        }
    }
}

enum TOTPError: LocalizedError {
    case emptySecret
    case invalidBase32
    case invalidURI
    case duplicateParameter
    case unsupportedType
    case unsupportedAlgorithm
    case unsupportedDigits
    case invalidPeriod
    case invalidDate
    case invalidDigest

    var errorDescription: String? {
        switch self {
        case .emptySecret: return "The TOTP secret cannot be empty."
        case .invalidBase32: return "The TOTP secret is not valid Base32, or its padding or trailing bits are invalid."
        case .invalidURI: return "The TOTP URI is invalid. Use a Base32 secret or an otpauth://totp URI."
        case .duplicateParameter: return "The TOTP URI contains duplicate parameters and cannot be parsed safely."
        case .unsupportedType: return "Only standard TOTP is supported; HOTP, Steam, and other specialized formats are unsupported."
        case .unsupportedAlgorithm: return "TOTP supports only SHA1, SHA256, and SHA512."
        case .unsupportedDigits: return "TOTP supports only 6 or 8 digits."
        case .invalidPeriod: return "The TOTP period must be an integer between 1 and 86400 seconds."
        case .invalidDate: return "The TOTP date is invalid and must be representable after 1970."
        case .invalidDigest: return "The TOTP digest is invalid, so a code cannot be generated."
        }
    }
}

enum TOTP {
    private enum Algorithm { case sha1, sha256, sha512 }
    private struct Parameters {
        let key: SymmetricKey
        let algorithm: Algorithm
        let digits: Int
        let period: Int
    }

    static func code(secret: String, date: Date = Date()) throws -> String {
        let parameters = try parse(secret)
        let time = date.timeIntervalSince1970
        let steps = floor(time / Double(parameters.period))
        // Double(UInt64.max) rounds to 2^64, so a strict inequality is intentional.
        guard time.isFinite, time >= 0, steps.isFinite,
              steps >= 0, steps < Double(UInt64.max) else { throw TOTPError.invalidDate }
        var counter = UInt64(steps).bigEndian
        let message = withUnsafeBytes(of: &counter) { Data($0) }
        let digest: [UInt8]
        switch parameters.algorithm {
        case .sha1:
            digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: parameters.key))
        case .sha256:
            digest = Array(HMAC<SHA256>.authenticationCode(for: message, using: parameters.key))
        case .sha512:
            digest = Array(HMAC<SHA512>.authenticationCode(for: message, using: parameters.key))
        }
        guard let last = digest.last else { throw TOTPError.invalidDigest }
        let offset = Int(last & 0x0F)
        guard offset + 3 < digest.count else { throw TOTPError.invalidDigest }
        let binary = (UInt32(digest[offset] & 0x7F) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])
        let modulus: UInt32 = parameters.digits == 8 ? 100_000_000 : 1_000_000
        let value = String(binary % modulus)
        return String(repeating: "0", count: parameters.digits - value.count) + value
    }

    /// Invalid configurations use the default only for display; code(secret:date:) still throws.
    static func period(secret: String) -> Int {
        (try? parse(secret).period) ?? 30
    }

    /// At an exact period boundary, a full new period remains. Invalid dates return zero.
    static func remaining(secret: String, date: Date = Date()) -> Double {
        let interval = Double(period(secret: secret))
        let time = date.timeIntervalSince1970
        guard time.isFinite, time >= 0, floor(time / interval) < Double(UInt64.max) else { return 0 }
        return interval - time.truncatingRemainder(dividingBy: interval)
    }

    private static func parse(_ input: String) throws -> Parameters {
        // Bound parsing work for untrusted imported URIs and keys.
        guard input.utf8.count <= 8192 else { throw TOTPError.invalidURI }
        let input = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty else { throw TOTPError.emptySecret }
        var key = input
        var algorithm = Algorithm.sha1
        var digits = 6
        var period = 30

        if input.contains(":") {
            guard let components = URLComponents(string: input),
                  components.scheme?.lowercased() == "otpauth",
                  components.user == nil, components.password == nil,
                  components.port == nil, components.fragment == nil else { throw TOTPError.invalidURI }
            guard components.host?.lowercased() == "totp" else { throw TOTPError.unsupportedType }
            guard components.path.hasPrefix("/"), components.path.count > 1,
                  let items = components.queryItems else { throw TOTPError.invalidURI }
            var values: [String: String] = [:]
            for item in items {
                let name = item.name.lowercased()
                guard values[name] == nil else { throw TOTPError.duplicateParameter }
                guard let value = item.value else { throw TOTPError.invalidURI }
                values[name] = value
            }
            let label = String(components.path.dropFirst()).lowercased()
                        if values["encoder"] != nil || values["counter"] != nil || values["steam"] != nil
                            || values["issuer"]?.lowercased() == "steam" || label == "steam" || label.hasPrefix("steam:") {
                throw TOTPError.unsupportedType
            }
            guard let secret = values["secret"], !secret.isEmpty else { throw TOTPError.emptySecret }
            key = secret
            if let value = values["algorithm"] {
                switch value.uppercased() {
                case "SHA1": algorithm = .sha1
                case "SHA256": algorithm = .sha256
                case "SHA512": algorithm = .sha512
                default: throw TOTPError.unsupportedAlgorithm
                }
            }
            if let value = values["digits"] {
                guard value == "6" || value == "8" else { throw TOTPError.unsupportedDigits }
                digits = value == "8" ? 8 : 6
            }
            if let value = values["period"] {
                guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
                      let parsed = Int(value), (1...86400).contains(parsed) else { throw TOTPError.invalidPeriod }
                period = parsed
            }
        }
        let data = try decodeBase32(key)
        return Parameters(key: SymmetricKey(data: data), algorithm: algorithm, digits: digits, period: period)
    }

    private static func decodeBase32(_ input: String) throws -> Data {
        let compact = input.filter { !$0.isWhitespace }
        guard !compact.isEmpty else { throw TOTPError.emptySecret }
        // Unicode case folding must not turn non-Base32 characters (such as ß) into valid letters.
        guard compact.utf8.allSatisfy({ $0 < 128 }) else { throw TOTPError.invalidBase32 }
        let bytes = Array(compact.uppercased().utf8)
        let contentCount = bytes.firstIndex(of: 61) ?? bytes.count
        let padding = bytes.count - contentCount
        guard bytes.dropFirst(contentCount).allSatisfy({ $0 == 61 }) else { throw TOTPError.invalidBase32 }
        let remainder = contentCount % 8
        let expectedPadding: Int
        switch remainder {
        case 0: expectedPadding = 0
        case 2: expectedPadding = 6
        case 4: expectedPadding = 4
        case 5: expectedPadding = 3
        case 7: expectedPadding = 1
        default: throw TOTPError.invalidBase32
        }
        guard contentCount > 0, padding == 0 || (padding == expectedPadding && bytes.count % 8 == 0) else {
            throw TOTPError.invalidBase32
        }
        var output = Data()
        output.reserveCapacity(contentCount * 5 / 8)
        var accumulator: UInt32 = 0
        var bits = 0
        for byte in bytes.prefix(contentCount) {
            let value: UInt32
            switch byte {
            case 65...90: value = UInt32(byte - 65)
            case 50...55: value = UInt32(byte - 50 + 26)
            default: throw TOTPError.invalidBase32
            }
            accumulator = (accumulator << 5) | value
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((accumulator >> bits) & 0xFF))
                accumulator &= (1 << bits) - 1
            }
        }
        guard accumulator == 0, !output.isEmpty else { throw TOTPError.invalidBase32 }
        return output
    }
}

enum SecureClipboard {
    @MainActor
    static func copy(_ text: String, clearAfter: TimeInterval = 30) {
        // A finite bound also makes conversion to Task.sleep's nanoseconds safe.
        let delay = clearAfter.isFinite ? min(86400, max(0, clearAfter)) : 30
        let pasteboard = UIPasteboard.general
        pasteboard.setItems([[UTType.utf8PlainText.identifier: text]], options: [
            .localOnly: true,
            .expirationDate: Date().addingTimeInterval(delay)
        ])
        let changeCount = pasteboard.changeCount
        Task { @MainActor in
            do {
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            } catch {
                return
            }
            // Never clear a subsequent copy, even if it contains the same text.
            guard pasteboard.changeCount == changeCount else { return }
            pasteboard.items = []
        }
    }
}

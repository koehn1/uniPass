# uniPass

uniPass is a completely offline, highly secure personal password manager designed exclusively for iOS and macOS. The project focuses on minimal dependency and robust local encryption to ensure user data privacy without relying on cloud synchronization.

Built for **Kiro Hackathon 2026**, uniPass keeps the vault under the user's control. The application does not require an account, a hosted service, or network access for its core workflows.

## Features

- **Local encrypted vault**: Protects passwords, usernames, websites, notes, TOTP secrets, custom fields, and attachments with authenticated encryption.
- **Strong master-password protection**: Uses a memory-cleared session, authenticated vault envelopes, independent salts, and guarded key derivation.
- **Secure local storage**: Uses protected files, atomic writes, external-change detection, and path-safe attachment I/O.
- **Biometric unlock**: Supports Face ID and Touch ID through the system Keychain and LocalAuthentication frameworks.
- **Password generator**: Creates cryptographically random passwords with configurable length, uppercase letters, lowercase letters, digits, and symbols.
- **TOTP support**: Generates six- and eight-digit one-time codes for standard TOTP configurations using SHA-1, SHA-256, or SHA-512.
- **Clipboard protection**: Copies sensitive values for a limited time and clears the app's clipboard content automatically.
- **Organization tools**: Supports folders, favorites, Recently Deleted, search, custom fields, multiple websites, and encrypted attachments.
- **Bitwarden import**: Imports unencrypted Bitwarden JSON exports, including supported attachment layouts, while retaining original source data for review.
- **Encrypted backups**: Exports and restores complete vault backups, including attachment ciphertext, without exposing plaintext vault data.
- **Manual file workflows**: Lets users choose a local directory or a user-controlled file provider location without making cloud synchronization a requirement.
- **Privacy-focused UI**: Applies sensitive-text protection, secure input, VoiceOver labels, Dynamic Type, and a centralized custom-font system.
- **Cross-platform Apple design**: Targets iOS and macOS through SwiftUI and Mac Catalyst with a shared encrypted storage model.

## Security and privacy

uniPass is local-first by design. Vault contents are encrypted before they are written to disk, and the application never needs to send passwords or plaintext vault data to a remote service. Users are responsible for protecting their master password and exported plaintext attachments.

The project intentionally keeps dependencies close to Apple's system frameworks, including SwiftUI, CryptoKit, Security, LocalAuthentication, and AVFoundation. Network synchronization code, when used with a user-controlled WebDAV or S3-compatible location, transfers encrypted vault data rather than plaintext secrets; it is optional and not required for normal use.

## Requirements

- iOS 16 or later
- macOS Ventura 13.7.6 or later through Mac Catalyst
- Xcode 15.2 or later

## Build

Open `uniPass.xcodeproj` in Xcode and choose the `uniPass` scheme. The custom-font validation script runs automatically as part of the application build.

To run the typography check directly:

```sh
python3 Scripts/check-custom-fonts.py
```

The application bundle identifier is `com.unipass.unipass`.

## Project status

uniPass is an active hackathon project. The current focus is dependable offline encryption, a small dependency surface, transparent local storage, and a privacy-preserving user experience for Apple platforms.

# uniPass Development Conventions

## Required typography rules

- All application text must use `uniPass/CustomFont.swift`; do not create page-specific font systems.
- The primary font for English, numbers, and punctuation is `uniPass/Fonts/LibreBaskerville-Regular.ttf`, PostScript name `LibreBaskerville-Regular`.
- The fallback font is `uniPass/Fonts/LXGWZhenKai.ttf`, PostScript name `LXGWZhenKai`. Use one shared font descriptor for mixed text and never alter user-provided text.
- SwiftUI text styles use `.customFont(.body)`, `.customFont(.headline)`, and related semantic entry points. Use `.customFont(size: 30, relativeTo: .title)` for special sizes. Ordinary text inheriting the root default font does not need a duplicate modifier.
- Use `CustomSection` for grouped lists and forms so body content, headers, and footers use the centralized font entry point.
- Do not use `.font(.system(...))`, `.font(.body)`, `Font.custom(...)`, `.fontWeight(...)`, `.bold()`, `.italic()`, `.monospaced()`, or `.monospacedDigit()`. The project has only regular font faces and must not substitute system fonts for bold or monospaced variants. Passwords, TOTP codes, paths, and JSON are included.
- SF Symbol icons may use `.font(CustomFont.symbol(size: ..., weight: ...))`; this entry point is only for `Image(systemName:)`, never for text, whole labels, or input controls. Site initials are text and must use `customFont`.
- New UIKit text controls must obtain fonts from `CustomFont.uiFont(...)`. If the build check needs an adjustment, extend the centralized wrapper instead of removing the check or adding scattered exemptions.
- Preserve Dynamic Type, VoiceOver, secure input, and sensitive-text protection. System file pickers, permission and biometric panels, native alerts, and characters not included in the bundled fonts should retain system behavior. Do not use private APIs or swizzling.
- Font resources are versioned under `uniPass/Fonts/`. Do not reference absolute developer-machine paths or ignored directories. Confirm font licensing and add license files before public distribution.

## Validation

Every build runs `Scripts/check-custom-fonts.py`; keep Xcode user-script sandboxing enabled. Add each new Swift file to `Scripts/CustomFontInputs.xcfilelist`, and add new source directories to the typography build-phase input paths so the sandbox can read them. Do not disable sandboxing or skip the check to work around permission errors. Run it independently with:

```sh
python3 Scripts/check-custom-fonts.py
```

After changing font logic, run `CustomFontTests` and inspect unlock, list, editing, settings, navigation titles, search, and mixed-script rendering. Support iOS 16+, Intel macOS Ventura 13.7.6, Mac Catalyst, and Xcode 15.2 without introducing APIs that require newer system versions.

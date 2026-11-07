import CoreText
import UIKit
import XCTest
@testable import uniPass

final class CustomFontTests: XCTestCase {
    func testBothFontFilesAreBundledWithExpectedNames() throws {
        for name in CustomFont.resourceNames {
            let url = try XCTUnwrap(Bundle.main.url(forResource: name, withExtension: "ttf", subdirectory: "Fonts"))
            let descriptors = try XCTUnwrap(CTFontManagerCreateFontDescriptorsFromURL(url as CFURL) as? [CTFontDescriptor])
            XCTAssertEqual(descriptors.count, 1)
            let descriptor = try XCTUnwrap(descriptors.first)
            let font = CTFontCreateWithFontDescriptor(descriptor, 17, nil)
            XCTAssertEqual(CTFontCopyPostScriptName(font) as String, name)
        }
    }

    func testLatinAndPunctuationResolveToCustomFonts() {
        for style in CustomFont.Style.allCases {
            let font = CustomFont.uiFont(style) as CTFont
            XCTAssertEqual(CTFontCopyPostScriptName(font) as String, CustomFont.latinName)
            for text in ["Password", "uniPass", "0123456789", "user@example.com", "!@#$%^&*()_+-=[]{};:'\"/?."] {
                let resolved = CTFontCreateForString(font, text as CFString, CFRange(location: 0, length: (text as NSString).length))
                XCTAssertEqual(CTFontCopyPostScriptName(resolved) as String, CustomFont.latinName, text)
            }
        }
    }

    func testMixedTextShapesUsingBothFontsWithoutChangingContent() throws {
        let text = "uniPass Vault Password123."
        let attributed = NSAttributedString(string: text, attributes: [.font: CustomFont.uiFont()])
        let line = CTLineCreateWithAttributedString(attributed)
        let runs = CTLineGetGlyphRuns(line) as! [CTRun]
        var names = Set<String>()
        for run in runs {
            let attributes = CTRunGetAttributes(run) as NSDictionary
            let font = try XCTUnwrap(attributes[kCTFontAttributeName]) as! CTFont
            let name = CTFontCopyPostScriptName(font) as String
            names.insert(name)
            let range = CTRunGetStringRange(run)
            let substring = (text as NSString).substring(with: NSRange(location: range.location, length: range.length))
            if substring.contains("Password123") { XCTAssertEqual(name, CustomFont.latinName) }
        }
        XCTAssertEqual(names, Set([CustomFont.latinName]))
        XCTAssertEqual(attributed.string, text)
    }

    func testDynamicTypeScalesWhilePreservingCascade() {
        for style in CustomFont.Style.allCases {
            let regular = CustomFont.uiFont(style, category: .large)
            let accessible = CustomFont.uiFont(style, category: .accessibilityExtraExtraExtraLarge)
            XCTAssertEqual(regular.pointSize, style.pointSize, accuracy: 0.1)
            XCTAssertGreaterThan(accessible.pointSize, regular.pointSize)
            XCTAssertEqual(accessible.fontName, CustomFont.latinName)
        }
        XCTAssertEqual(CustomFont.uiFont(.title, size: 30).pointSize, 30, accuracy: 0.1)
    }

    @MainActor
    func testNavigationAndNativeControlsUseCustomFont() throws {
        CustomFont.configureAppearance()
        defer { CustomFont.configureAppearance(category: UIApplication.shared.preferredContentSizeCategory) }
        let bar = UINavigationBar.appearance().standardAppearance
        let title = try XCTUnwrap(bar.titleTextAttributes[.font] as? UIFont)
        let largeTitle = try XCTUnwrap(bar.largeTitleTextAttributes[.font] as? UIFont)
        XCTAssertEqual(title.fontName, CustomFont.latinName)
        XCTAssertEqual(largeTitle.fontName, CustomFont.latinName)
        XCTAssertEqual(UITextField.appearance().font?.fontName, CustomFont.latinName)
        XCTAssertEqual(UITextView.appearance().font?.fontName, CustomFont.latinName)
        XCTAssertEqual(UISearchTextField.appearance().font?.fontName, CustomFont.latinName)
    }
}

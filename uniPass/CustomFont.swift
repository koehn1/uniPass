import CoreText
import SwiftUI
import UIKit

/// All application text uses this cascade: Latin first, then the fallback font.
/// Putting the fallback font first would also render its Latin glyphs.
enum CustomFont {
    static let latinName = "LibreBaskerville-Regular"
    static let chineseName = "LXGWZhenKai"
    static let resourceNames = [latinName, chineseName]

    enum Style: CaseIterable {
        case largeTitle, title, title2, title3, headline, body, callout, subheadline, footnote, caption, caption2

        var textStyle: UIFont.TextStyle {
            switch self {
            case .largeTitle: return .largeTitle
            case .title: return .title1
            case .title2: return .title2
            case .title3: return .title3
            case .headline: return .headline
            case .body: return .body
            case .callout: return .callout
            case .subheadline: return .subheadline
            case .footnote: return .footnote
            case .caption: return .caption1
            case .caption2: return .caption2
            }
        }

        var pointSize: CGFloat {
            switch self {
            case .largeTitle: return 34
            case .title: return 28
            case .title2: return 22
            case .title3: return 20
            case .headline, .body: return 17
            case .callout: return 16
            case .subheadline: return 15
            case .footnote: return 13
            case .caption: return 12
            case .caption2: return 11
            }
        }
    }

    private static let registration: Void = {
        for name in resourceNames {
            guard let url = Bundle.main.url(forResource: name, withExtension: "ttf", subdirectory: "Fonts") else {
                preconditionFailure("Missing bundled custom font: Fonts/\(name).ttf")
            }
            if UIFont(name: name, size: 17) == nil {
                var error: Unmanaged<CFError>?
                let registered = CTFontManagerRegisterFontsForURL(url as CFURL, .process, &error)
                precondition(registered, "Cannot register custom font \(name): \(String(describing: error?.takeRetainedValue()))")
            }
            precondition(UIFont(name: name, size: 17) != nil, "Invalid custom font PostScript name: \(name)")
        }
    }()

    static func uiFont(_ style: Style = .body, size: CGFloat? = nil,
                       category: UIContentSizeCategory = .large) -> UIFont {
        _ = registration
        let pointSize = size ?? style.pointSize
        let descriptor = UIFontDescriptor(fontAttributes: [
            .name: latinName,
            .cascadeList: [UIFontDescriptor(name: chineseName, size: pointSize)]
        ])
        let base = UIFont(descriptor: descriptor, size: pointSize)
        return UIFontMetrics(forTextStyle: style.textStyle).scaledFont(
            for: base, compatibleWith: UITraitCollection(preferredContentSizeCategory: category))
    }

    /// SF Symbols are icons, not a permitted system-font shortcut for text.
    static func symbol(size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight)
    }

    @MainActor
    static func configureAppearance(category: UIContentSizeCategory = .large) {
        let navigation = UINavigationBarAppearance()
        navigation.configureWithDefaultBackground()
        navigation.titleTextAttributes = [.font: uiFont(.headline, category: category)]
        navigation.largeTitleTextAttributes = [.font: uiFont(.largeTitle, category: category)]
        let bar = UINavigationBar.appearance()
        bar.standardAppearance = navigation
        bar.scrollEdgeAppearance = navigation
        bar.compactAppearance = navigation
        bar.compactScrollEdgeAppearance = navigation

        for state in [UIControl.State.normal, .highlighted, .disabled, .selected] {
            UIBarButtonItem.appearance().setTitleTextAttributes([.font: uiFont(.body, category: category)], for: state)
            UISegmentedControl.appearance().setTitleTextAttributes([.font: uiFont(.subheadline, category: category)], for: state)
        }
        let tabs = UITabBarAppearance()
        tabs.configureWithDefaultBackground()
        for layout in [tabs.stackedLayoutAppearance, tabs.inlineLayoutAppearance, tabs.compactInlineLayoutAppearance] {
            for state in [layout.normal, layout.selected, layout.disabled, layout.focused] {
                state.titleTextAttributes = [.font: uiFont(.caption, category: category)]
            }
        }
        UITabBar.appearance().standardAppearance = tabs
        UITabBar.appearance().scrollEdgeAppearance = tabs
        UITextField.appearance().font = uiFont(.body, category: category)
        UITextView.appearance().font = uiFont(.body, category: category)
        UISearchTextField.appearance().font = uiFont(.body, category: category)
    }
}

private struct CustomFontModifier: ViewModifier {
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    let style: CustomFont.Style
    var size: CGFloat?

    func body(content: Content) -> some View {
        content.font(Font(CustomFont.uiFont(style, size: size, category: dynamicTypeSize.contentSizeCategory) as CTFont))
    }
}

extension View {
    func customFont(_ style: CustomFont.Style = .body) -> some View {
        modifier(CustomFontModifier(style: style))
    }

    func customFont(size: CGFloat, relativeTo style: CustomFont.Style = .body) -> some View {
        modifier(CustomFontModifier(style: style, size: size))
    }
}

private extension DynamicTypeSize {
    var contentSizeCategory: UIContentSizeCategory {
        switch self {
        case .xSmall: return .extraSmall
        case .small: return .small
        case .medium: return .medium
        case .large: return .large
        case .xLarge: return .extraLarge
        case .xxLarge: return .extraExtraLarge
        case .xxxLarge: return .extraExtraExtraLarge
        case .accessibility1: return .accessibilityMedium
        case .accessibility2: return .accessibilityLarge
        case .accessibility3: return .accessibilityExtraLarge
        case .accessibility4: return .accessibilityExtraExtraLarge
        case .accessibility5: return .accessibilityExtraExtraExtraLarge
        @unknown default: return .large
        }
    }
}

/// Native sections otherwise introduce their own system header/footer fonts.
struct CustomSection<Content: View, Header: View, Footer: View>: View {
    private let content: Content
    private let header: Header
    private let footer: Footer

    init(@ViewBuilder content: () -> Content, @ViewBuilder header: () -> Header,
         @ViewBuilder footer: () -> Footer) {
        self.content = content()
        self.header = header()
        self.footer = footer()
    }

    var body: some View {
        Section {
            content.customFont()
        } header: {
            header.customFont(.footnote)
        } footer: {
            footer.customFont(.footnote)
        }
    }
}

extension CustomSection where Header == EmptyView, Footer == EmptyView {
    init(@ViewBuilder content: () -> Content) {
        self.init(content: content, header: { EmptyView() }, footer: { EmptyView() })
    }
}

extension CustomSection where Header == Text, Footer == EmptyView {
    init(_ title: LocalizedStringKey, @ViewBuilder content: () -> Content) {
        self.init(content: content, header: { Text(title) }, footer: { EmptyView() })
    }
}

extension CustomSection where Footer == EmptyView {
    init(@ViewBuilder content: () -> Content, @ViewBuilder header: () -> Header) {
        self.init(content: content, header: header, footer: { EmptyView() })
    }
}

extension CustomSection where Header == EmptyView {
    init(@ViewBuilder content: () -> Content, @ViewBuilder footer: () -> Footer) {
        self.init(content: content, header: { EmptyView() }, footer: footer)
    }
}

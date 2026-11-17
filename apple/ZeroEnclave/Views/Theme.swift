import SwiftUI

enum Theme {
    /// Same background as the tabs, so locking and unlocking do not change the backdrop.
    static let canvas = Color(.systemBackground)
    static let ink = Color("Ink")
    static let mint = Color("AccentColor")
    /// Text and symbols on mint: white in light mode, near black on the bright dark-mode mint.
    static let onAccent = Color("OnAccent")
    /// Background of the premium hero and banner; the dark end keeps white text readable.
    /// Mint that keeps white text readable in light and dark mode (tiles, banners).
    static let deepMint = Color(red: 0.04, green: 0.48, blue: 0.33)
    static let premiumGradient = LinearGradient(
        colors: [deepMint, Color(red: 0.03, green: 0.29, blue: 0.34)],
        startPoint: .topLeading, endPoint: .bottomTrailing)
    /// Background of the Enclave Link banner; graphite like the band of the app icon.
    static let linkGradient = LinearGradient(
        colors: [Color(red: 0.48, green: 0.48, blue: 0.47), Color(red: 0.13, green: 0.13, blue: 0.13)],
        startPoint: .topLeading, endPoint: .bottomTrailing)
}

/// App icon image used on the welcome, unlock and premium screens.
struct AppMark: View {
    /// Size of the Z mark on the privacy cover (UIKit window and SwiftUI overlay).
    static let coverSize: CGFloat = 96

    var size: CGFloat = 88

    var body: some View {
        Image(AppIconChoice.current.logoName)
            .resizable()
            .interpolation(.high)
            .scaledToFit()
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

extension View {
    /// Shared look of password entry: centered, no autocorrection or capitalization.
    func masterPasswordStyle() -> some View {
        multilineTextAlignment(.center)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .privacySensitive()
    }
}

extension View {
    /// Rounded, filled container shared by text inputs (matches `PasswordInput`).
    func inputFieldContainer() -> some View {
        padding(.horizontal, 16)
            .frame(height: 52)
            .background(.fill.tertiary, in: .rect(cornerRadius: 16))
    }
}

/// Short error or warning: the symbol carries the color, the text stays readable.
struct Notice: View {
    enum Tone { case error, warning }

    private let text: Text
    private let tone: Tone

    init(_ key: LocalizedStringKey, tone: Tone = .error) {
        text = Text(key)
        self.tone = tone
    }

    init(verbatim string: String, tone: Tone = .error) {
        text = Text(string)
        self.tone = tone
    }

    var body: some View {
        Label {
            text
                .foregroundStyle(.primary)
                // Never truncated: on a crowded screen the spacers shrink instead.
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: tone == .error ? "exclamationmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(tone == .error ? .red : .orange)
        }
        .font(.footnote)
    }
}

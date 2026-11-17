import SwiftUI

/// Colored rounded tile with a white symbol, as in the system Settings.
struct SettingsIcon: View {
    let systemName: String
    var tint: Color = Theme.deepMint
    var size: CGFloat = 30

    var body: some View {
        Image(systemName: systemName)
            .font(.system(size: size * 0.55, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(tint.gradient, in: .rect(cornerRadius: size * 0.27))
            .accessibilityHidden(true)
    }
}

/// Settings row label: icon tile plus title.
struct SettingsLabel: View {
    let title: LocalizedStringKey
    let systemName: String
    var tint: Color = Theme.deepMint

    var body: some View {
        HStack(spacing: 14) {
            SettingsIcon(systemName: systemName, tint: tint)
            Text(title)
        }
    }
}

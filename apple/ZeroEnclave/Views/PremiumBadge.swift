import SwiftUI

/// Small capsule that marks a premium feature; hidden once premium is active.
struct PremiumBadge: View {
    @Environment(Entitlements.self) private var entitlements

    var body: some View {
        if !entitlements.hasPremium {
            badge
        }
    }

    private var badge: some View {
        Text("Premium")
            .font(.caption2.weight(.semibold))
            .foregroundStyle(Theme.mint)
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(Theme.mint.opacity(0.15), in: .capsule)
            .accessibilityLabel("Premium feature")
    }
}

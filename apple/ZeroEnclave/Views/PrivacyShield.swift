import SwiftUI

/// Opaque cover shown whenever the scene is not active (app switcher, snapshots).
struct PrivacyShield: View {
    var body: some View {
        // Same look as the privacy window; follows light and dark mode.
        ZStack {
            Color(uiColor: .systemBackground)
            Image(AppIconChoice.current.markName)
                .resizable()
                .interpolation(.high)
                .scaledToFit()
                .frame(width: AppMark.coverSize, height: AppMark.coverSize)
                .accessibilityHidden(true)
        }
        .ignoresSafeArea()
    }
}

/// Covers the view whenever the scene is not active. Applied to every presented view because
/// modals sit above the root. No animation: the cover must be in place before the snapshot.
private struct PrivacyCoverModifier: ViewModifier {
    var isEnabled = true
    @Environment(\.scenePhase) private var scenePhase

    func body(content: Content) -> some View {
        content.overlay {
            if isEnabled, scenePhase != .active {
                PrivacyShield()
                    .transition(.identity)
            }
        }
        .transaction { $0.animation = nil }
    }
}

extension View {
    func privacyCover(isEnabled: Bool = true) -> some View { modifier(PrivacyCoverModifier(isEnabled: isEnabled)) }
}

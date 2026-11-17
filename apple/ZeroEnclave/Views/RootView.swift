import SwiftUI
import UIKit

struct RootView: View {
    let vault: VaultService
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        ZStack {
            Theme.canvas.ignoresSafeArea()
            content
        }
        .privacyCover(isEnabled: vault.state.needsPrivacyCover)
        .tint(Theme.mint)
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { vault.lockIfNeeded() }
        }
        .onReceive(
            NotificationCenter.default.publisher(for: UIApplication.didReceiveMemoryWarningNotification)
        ) { _ in
            vault.lockIfNeeded()
        }
    }

    @ViewBuilder
    private var content: some View {
        switch vault.state {
        case .noVault:
            WelcomeView(vault: vault)
        case .onboarding:
            OnboardingView(vault: vault)
        case .recoveryKeyReview:
            RecoveryKeyView(recoveryKey: vault.pendingRecoveryKey ?? "") {
                vault.acknowledgeRecoveryKey()
                vault.finishOnboarding()
            }
        case .locked:
            UnlockView(vault: vault)
        case .unlocked:
            UnlockedView(vault: vault)
                .onAnyTouch { vault.noteActivity() }
        }
    }
}

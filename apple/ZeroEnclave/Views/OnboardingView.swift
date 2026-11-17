import SwiftUI

struct OnboardingView: View {
    let vault: VaultService
    @State private var step = Step.password

    private enum Step { case password, recoveryKey, done }

    var body: some View {
        switch step {
        case .password:
            CreatePasswordView(vault: vault) { step = .recoveryKey }
        case .recoveryKey:
            RecoveryKeyView(recoveryKey: vault.pendingRecoveryKey ?? "") {
                vault.acknowledgeRecoveryKey()
                step = .done
            }
        case .done:
            DoneView { vault.finishOnboarding() }
        }
    }
}

private struct DoneView: View {
    /// Follows Dynamic Type instead of a fixed point size.
    @ScaledMetric(relativeTo: .largeTitle) private var iconSize: CGFloat = 72

    let onOpen: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: iconSize))
                .foregroundStyle(Theme.mint)
                .accessibilityHidden(true)
            Text("Your vault is ready")
                .font(.title.weight(.bold))
            Text("The vault locks automatically when you leave the app or stop using it.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            VStack(alignment: .leading, spacing: 12) {
                tip("plus", "Import photos with the + button.")
                tip("lock.fill", "Lock the vault any time with the lock button.")
                tip("doc.text", "Save your recovery key in a password manager or on paper.")
            }
            .padding(.top, 8)
            Spacer()
            Button(action: onOpen) {
                Text("Open vault").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .foregroundStyle(Theme.onAccent)
            .controlSize(.large)
        }
        .padding(24)
    }

    private func tip(_ symbol: String, _ text: LocalizedStringKey) -> some View {
        Label {
            Text(text)
        } icon: {
            Image(systemName: symbol)
                .foregroundStyle(Theme.mint)
                .frame(width: 24)
        }
        .font(.subheadline)
    }
}

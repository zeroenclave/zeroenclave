import SwiftUI

/// New recovery key in steps, like the PIN setup: confirm with the master password, then
/// show the key with the same confirmation as onboarding.
struct RotateRecoveryFlow: View {
    let vault: VaultService
    let onDone: () -> Void

    @State private var newKey: String?
    @State private var password = ""
    @State private var confirmRotate = false
    @State private var message: String?
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Group {
                if let newKey {
                    RecoveryKeyView(recoveryKey: newKey, onConfirmed: onDone)
                        .transition(.move(edge: .trailing).combined(with: .opacity))
                } else {
                    passwordStep
                        .transition(.move(edge: .leading).combined(with: .opacity))
                }
            }
            .animation(.snappy, value: newKey != nil)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if newKey == nil {
                        Button("Cancel", systemImage: "xmark", action: onDone)
                            .disabled(vault.isWorking)
                    }
                }
            }
        }
        // The new key must be confirmed as saved; the old one no longer works.
        .interactiveDismissDisabled(vault.isWorking || newKey != nil)
    }

    private var passwordStep: some View {
        ScrollView {
            VStack(spacing: 0) {
                FlowHeader(
                    icon: "lifepreserver.fill", step: Text("Step 1 of 2"),
                    title: Text("Confirm with master password"),
                    subtitle: message
                        ?? String(localized: "The current recovery key stops working immediately."),
                    isError: message != nil)
                VStack(spacing: 16) {
                    PasswordInput(
                        title: "Master password", text: $password, onSubmit: { confirmRotate = true },
                        focus: $focused)
                    Button {
                        confirmRotate = true
                    } label: {
                        Group {
                            if vault.isWorking { ProgressView() } else { Text("Create new key") }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glassProminent)
                    .foregroundStyle(Theme.onAccent)
                    .controlSize(.large)
                    .disabled(password.isEmpty || vault.isWorking)
                }
                .padding(.horizontal, 24)
                .padding(.top, 32)
            }
            .padding(.vertical, 24)
            .frame(maxWidth: .infinity)
        }
        .scrollBounceBehavior(.basedOnSize)
        .scrollDismissesKeyboard(.interactively)
        .autoFocus($focused)
        .confirmSheet(
            isPresented: $confirmRotate, systemImage: "exclamationmark.triangle.fill",
            title: "Replace the recovery key?",
            message: "The old key can no longer open your vault.",
            actions: [ConfirmAction(title: "Replace", role: .destructive, action: rotate)])
    }

    private func rotate() {
        guard !password.isEmpty, !vault.isWorking else { return }
        let value = password
        password = ""
        message = nil
        Task {
            switch await vault.rotateRecoveryKey(password: value) {
            case .success(let key):
                focused = false
                newKey = key
            case .failure(let failure):
                message = failure.message
                focused = true
            }
        }
    }
}

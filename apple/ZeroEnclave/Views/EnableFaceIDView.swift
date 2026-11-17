import SwiftUI

/// Face ID setup in the style of the PIN setup: confirm with the master password, then done.
struct EnableFaceIDView: View {
    let vault: VaultService
    let onDone: () -> Void

    @State private var password = ""
    @State private var message: String?
    @State private var done = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                header
                Spacer(minLength: 24)
                content
                    .id(done)
                    .transition(
                        .asymmetric(
                            insertion: .move(edge: .trailing).combined(with: .opacity),
                            removal: .move(edge: .leading).combined(with: .opacity)))
                Spacer(minLength: 24)
            }
            .frame(maxWidth: .infinity)
            .animation(.snappy, value: done)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if !done {
                        Button("Cancel", systemImage: "xmark", action: onDone)
                            .disabled(vault.isWorking)
                    }
                }
            }
        }
        .interactiveDismissDisabled(vault.isWorking)
        .sensoryFeedback(.success, trigger: done) { _, new in new }
    }

    private var header: some View {
        FlowHeader(
            icon: done ? "checkmark.circle.fill" : "faceid",
            title: Text(done ? "Face ID is on" : "Turn on Face ID"), subtitle: subtitle,
            isError: message != nil, bounce: done)
    }

    private var subtitle: String {
        if let message { return message }
        return done
            ? String(localized: "Next time, Face ID opens the vault.")
            : String(localized: "Your master password confirms the change.")
    }

    @ViewBuilder
    private var content: some View {
        if done {
            Button(action: onDone) {
                Text("Done").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .foregroundStyle(Theme.onAccent)
            .controlSize(.large)
            .padding(.horizontal, 24)
        } else {
            VStack(spacing: 16) {
                PasswordInput(
                    title: "Master password", text: $password, onSubmit: enable, focus: $passwordFocused)
                Button(action: enable) {
                    Group {
                        if vault.isWorking { ProgressView() } else { Text("Turn on Face ID") }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .foregroundStyle(Theme.onAccent)
                .controlSize(.large)
                .disabled(password.isEmpty || vault.isWorking)
            }
            .padding(.horizontal, 24)
            .autoFocus($passwordFocused)
        }
    }

    private func enable() {
        guard !password.isEmpty, !vault.isWorking else { return }
        let value = password
        password = ""
        message = nil
        Task {
            if let failure = await vault.enableBiometrics(password: value) {
                message = failure
                passwordFocused = true
            } else {
                passwordFocused = false
                done = true
            }
        }
    }
}

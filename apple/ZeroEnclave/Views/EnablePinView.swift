import SwiftUI

/// PIN setup in steps: choose the PIN, repeat it, confirm with the master password.
struct EnablePinView: View {
    let vault: VaultService
    let onDone: () -> Void

    private enum Step: Int, Comparable {
        case create, confirm, password, done
        static func < (a: Step, b: Step) -> Bool { a.rawValue < b.rawValue }
    }

    @State private var step = Step.create
    @State private var pin = ""
    @State private var chosen = ""
    @State private var password = ""
    @State private var message: String?
    @State private var shake = 0
    @State private var feedback = PinPad.Feedback.none
    @FocusState private var passwordFocused: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                header
                Spacer(minLength: 24)
                content
                    .id(step)
                    .transition(
                        .asymmetric(
                            insertion: .move(edge: .trailing).combined(with: .opacity),
                            removal: .move(edge: .leading).combined(with: .opacity)))
                Spacer(minLength: 24)
            }
            .frame(maxWidth: .infinity)
            .animation(.snappy, value: step)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if step == .done {
                        EmptyView()
                    } else {
                        Button("Cancel", systemImage: "xmark", action: onDone)
                            .disabled(vault.isWorking)
                    }
                }
            }
        }
        .interactiveDismissDisabled(vault.isWorking || step != .create)
    }

    private var header: some View {
        FlowHeader(
            icon: step == .done ? "checkmark.circle.fill" : "circle.grid.3x3.fill",
            step: step == .done ? nil : Text("Step \(step.rawValue + 1) of 3"),
            title: Text(title), subtitle: subtitle, isError: message != nil, bounce: step == .done)
    }

    private var title: LocalizedStringKey {
        switch step {
        case .create: "Choose a PIN"
        case .confirm: "Repeat the PIN"
        case .password: "Confirm with master password"
        case .done: "PIN is on"
        }
    }

    private var subtitle: String {
        if let message { return message }
        return switch step {
        case .create: String(localized: "Six digits to unlock the vault quickly.")
        case .confirm: String(localized: "Enter the same six digits again.")
        case .password: String(localized: "Your master password confirms the change.")
        case .done: String(localized: "After a wrong PIN, Zero Enclave asks for the master password once.")
        }
    }

    @ViewBuilder
    private var content: some View {
        switch step {
        case .create, .confirm:
            PinPad(pin: $pin, shake: shake, feedback: feedback, onComplete: pinEntered)
        case .password:
            VStack(spacing: 16) {
                PasswordInput(
                    title: "Master password", text: $password, onSubmit: enable, focus: $passwordFocused)
                Button(action: enable) {
                    Group {
                        if vault.isWorking { ProgressView() } else { Text("Turn on PIN") }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .foregroundStyle(Theme.onAccent)
                .controlSize(.large)
                .disabled(password.isEmpty || vault.isWorking)
                Button("Choose another PIN", action: restart)
                    .foregroundStyle(Theme.mint)
                    .disabled(vault.isWorking)
            }
            .padding(.horizontal, 24)
            .autoFocus($passwordFocused)
        case .done:
            Button(action: onDone) {
                Text("Done").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .foregroundStyle(Theme.onAccent)
            .controlSize(.large)
            .padding(.horizontal, 24)
        }
    }

    private func pinEntered(_ value: String) {
        Task {
            // Let the sixth dot fill before the page moves on.
            try? await Task.sleep(for: .milliseconds(150))
            if step == .create {
                chosen = value
                pin = ""
                message = nil
                step = .confirm
            } else if value == chosen {
                feedback = .accepted
                try? await Task.sleep(for: .milliseconds(350))
                pin = ""
                feedback = .none
                message = nil
                step = .password
            } else {
                shake += 1
                pin = ""
                chosen = ""
                message = String(localized: "The PINs do not match. Try again.")
                step = .create
            }
        }
    }

    private func restart() {
        chosen = ""
        pin = ""
        password = ""
        message = nil
        step = .create
    }

    private func enable() {
        guard !password.isEmpty, !vault.isWorking else { return }
        let (secret, code) = (password, chosen)
        password = ""
        message = nil
        Task {
            if let failure = await vault.enablePin(password: secret, pin: code) {
                message = failure
                passwordFocused = true
            } else {
                chosen = ""
                passwordFocused = false
                step = .done
            }
        }
    }
}

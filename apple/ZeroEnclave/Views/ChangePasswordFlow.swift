import SwiftUI

/// Master password change in steps, like the PIN setup: choose, repeat, confirm with the
/// current password. The KDF is recalibrated for this device.
struct ChangePasswordFlow: View {
    let vault: VaultService
    let onDone: () -> Void

    private enum Step: Int {
        case create, confirm, current, done
    }

    @State private var step = Step.create
    @State private var password = ""
    @State private var repeated = ""
    @State private var current = ""
    @State private var message: String?
    @FocusState private var focused: Bool

    private let policy = PasswordPolicy()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 0) {
                    header
                    content
                        .id(step)
                        .transition(
                            .asymmetric(
                                insertion: .move(edge: .trailing).combined(with: .opacity),
                                removal: .move(edge: .leading).combined(with: .opacity)))
                        .padding(.top, 24)
                }
                .padding(.top, 8)
                .padding(.bottom, 24)
                .frame(maxWidth: .infinity)
            }
            .scrollBounceBehavior(.basedOnSize)
            .scrollDismissesKeyboard(.interactively)
            .safeAreaInset(edge: .bottom) { actions.background(Theme.canvas) }
            .animation(.snappy, value: step)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if step != .done {
                        Button("Cancel", systemImage: "xmark", action: onDone)
                            .disabled(vault.isWorking)
                    }
                }
            }
        }
        .interactiveDismissDisabled(vault.isWorking || (step != .create && step != .done))
        .autoFocus($focused, id: step)
    }

    private var header: some View {
        FlowHeader(
            icon: step == .done ? "checkmark.circle.fill" : "key.fill",
            step: step == .done ? nil : Text("Step \(step.rawValue + 1) of 3"),
            title: Text(title), subtitle: subtitle, isError: message != nil, bounce: step == .done)
    }

    private var title: LocalizedStringKey {
        switch step {
        case .create: "Choose a new master password"
        case .confirm: "Repeat the new password"
        case .current: "Confirm with current password"
        case .done: "Password changed"
        }
    }

    private var subtitle: String {
        if let message { return message }
        return switch step {
        case .create: String(localized: "Your photos stay as they are. Only the password changes.")
        case .confirm: String(localized: "Enter the same password again.")
        case .current:
            String(localized: "This turns off the panic password, Face ID and PIN. Older backups still open with the old password.")
        case .done: String(localized: "Use the new password the next time you unlock the vault.")
        }
    }

    /// Fields scroll with the header; the buttons stay above the keyboard.
    private var content: some View {
        VStack(spacing: 16) {
            switch step {
            case .create:
                PasswordInput(
                    title: "New password", text: $password, contentType: .newPassword,
                    onSubmit: next, focus: $focused)
                StrengthMeter(evaluation: policy.evaluate(password))
            case .confirm:
                PasswordInput(
                    title: "Repeat new password", text: $repeated, contentType: .newPassword,
                    onSubmit: next, focus: $focused)
            case .current:
                PasswordInput(title: "Current password", text: $current, onSubmit: submit, focus: $focused)
            case .done:
                EmptyView()
            }
        }
        .padding(.horizontal, 24)
    }

    private var actions: some View {
        VStack(spacing: 12) {
            switch step {
            case .create:
                primary("Continue", disabled: !policy.evaluate(password).isAcceptable, action: next)
            case .confirm:
                primary("Continue", disabled: repeated.isEmpty, action: next)
            case .current:
                Button(action: submit) {
                    Group {
                        if vault.isWorking {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text(vault.isCalibrating ? "Preparing…" : "Changing password…")
                            }
                        } else {
                            Text("Change password")
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .foregroundStyle(Theme.onAccent)
                .controlSize(.large)
                .disabled(current.isEmpty || vault.isWorking)
                Button("Choose another password", action: restart)
                    .foregroundStyle(Theme.mint)
                    .disabled(vault.isWorking)
            case .done:
                primary("Done", disabled: false, action: onDone)
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 12)
    }

    private func primary(
        _ title: LocalizedStringKey, disabled: Bool, action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Text(title).frame(maxWidth: .infinity)
        }
        .buttonStyle(.glassProminent)
        .foregroundStyle(Theme.onAccent)
        .controlSize(.large)
        .disabled(disabled)
    }

    private func next() {
        message = nil
        switch step {
        case .create:
            guard policy.evaluate(password).isAcceptable else { return }
            step = .confirm
        case .confirm:
            guard !repeated.isEmpty else { return }
            if policy.canContinue(password: password, confirmation: repeated) {
                step = .current
            } else {
                password = ""
                repeated = ""
                message = String(localized: "The passwords do not match.")
                step = .create
            }
        default:
            break
        }
    }

    private func restart() {
        password = ""
        repeated = ""
        current = ""
        message = nil
        step = .create
    }

    private func submit() {
        guard !current.isEmpty, !vault.isWorking else { return }
        let (old, new) = (current, password)
        current = ""
        message = nil
        Task {
            if let failure = await vault.changePassword(old: old, new: new) {
                message = failure
                focused = true
            } else {
                password = ""
                repeated = ""
                step = .done
            }
        }
    }
}

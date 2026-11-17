import SwiftUI

/// Panic password in steps, like the PIN setup: choose, repeat, confirm with the master
/// password. Turning it off is a single master password step.
struct DuressSetupFlow: View {
    enum Mode: Identifiable {
        case set, disable
        var id: Self { self }
    }

    let vault: VaultService
    let mode: Mode
    let onDone: () -> Void

    private enum Step: Int {
        case create, confirm, password, done
    }

    @State private var step: Step
    @State private var panic = ""
    @State private var repeated = ""
    @State private var master = ""
    @State private var message: String?
    /// Whether a panic password existed when the flow started (set vs. change).
    @State private var wasEnabled: Bool
    @FocusState private var focused: Bool

    private let gate = DuressSetupGate()

    init(vault: VaultService, mode: Mode, onDone: @escaping () -> Void) {
        self.vault = vault
        self.mode = mode
        self.onDone = onDone
        _step = State(initialValue: mode == .set ? .create : .password)
        _wasEnabled = State(initialValue: vault.duressEnabled)
    }

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
            icon: step == .done ? "checkmark.circle.fill" : "flame.fill",
            step: step == .done || mode == .disable ? nil : Text("Step \(step.rawValue + 1) of 3"),
            title: Text(title), subtitle: subtitle, isError: message != nil, bounce: step == .done)
    }

    private var title: LocalizedStringKey {
        switch (mode, step) {
        case (.disable, .done): "Panic password is off"
        case (.disable, _): "Turn off panic password"
        case (_, .create): "Choose a panic password"
        case (_, .confirm): "Repeat the panic password"
        case (_, .password): "Confirm with master password"
        case (_, .done): wasEnabled ? "Panic password changed" : "Panic password is on"
        }
    }

    private var subtitle: String {
        if let message { return message }
        return switch (mode, step) {
        case (.disable, .done): String(localized: "Entering it no longer destroys the vault.")
        case (_, .create): String(localized: "At least 12 characters, different from your master password.")
        case (_, .confirm): String(localized: "Enter the same password again.")
        case (_, .password): String(localized: "Your master password confirms the change.")
        case (_, .done): String(localized: "Entered on the unlock screen, it destroys the vault on this device.")
        }
    }

    /// Fields scroll with the header; the buttons stay above the keyboard.
    private var content: some View {
        VStack(spacing: 16) {
            switch step {
            case .create:
                PasswordInput(
                    title: "Panic password", text: $panic, contentType: .newPassword,
                    onSubmit: next, focus: $focused)
                StrengthMeter(evaluation: gate.policy.evaluate(panic))
            case .confirm:
                PasswordInput(
                    title: "Repeat panic password", text: $repeated, contentType: .newPassword,
                    onSubmit: next, focus: $focused)
            case .password:
                PasswordInput(title: "Master password", text: $master, onSubmit: submit, focus: $focused)
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
                primary("Continue", disabled: !gate.policy.evaluate(panic).isAcceptable, action: next)
            case .confirm:
                primary("Continue", disabled: repeated.isEmpty, action: next)
            case .password:
                primary(
                    mode == .disable ? "Turn off" : (wasEnabled ? "Change panic password" : "Turn on panic password"),
                    disabled: master.isEmpty || vault.isWorking, working: vault.isWorking,
                    destructive: mode == .disable, action: submit)
                if mode == .set {
                    Button("Choose another panic password", action: restart)
                        .foregroundStyle(Theme.mint)
                        .disabled(vault.isWorking)
                }
            case .done:
                primary("Done", disabled: false, action: onDone)
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 12)
    }

    private func primary(
        _ title: LocalizedStringKey, disabled: Bool, working: Bool = false, destructive: Bool = false,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Group {
                if working { ProgressView() } else { Text(title) }
            }
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.glassProminent)
        .tint(destructive ? .red : Theme.mint)
        .foregroundStyle(destructive ? .white : Theme.onAccent)
        .controlSize(.large)
        .disabled(disabled)
    }

    private func next() {
        message = nil
        switch step {
        case .create:
            guard gate.policy.evaluate(panic).isAcceptable else { return }
            step = .confirm
        case .confirm:
            guard !repeated.isEmpty else { return }
            if gate.policy.canContinue(password: panic, confirmation: repeated) {
                step = .password
            } else {
                panic = ""
                repeated = ""
                message = String(localized: "The passwords do not match.")
                step = .create
            }
        default:
            break
        }
    }

    private func restart() {
        panic = ""
        repeated = ""
        master = ""
        message = nil
        step = .create
    }

    private func submit() {
        guard !master.isEmpty, !vault.isWorking else { return }
        let (password, duress) = (master, panic)
        master = ""
        message = nil
        Task {
            let failure =
                mode == .disable
                ? await vault.disableDuress(masterPassword: password)
                : await vault.setDuress(masterPassword: password, duress: duress)
            if let failure {
                message = failure
                focused = true
            } else {
                panic = ""
                repeated = ""
                step = .done
            }
        }
    }
}

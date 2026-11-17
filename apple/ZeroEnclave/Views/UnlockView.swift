import SwiftUI

struct UnlockView: View {
    let vault: VaultService

    @Environment(Entitlements.self) private var entitlements
    @Environment(\.scenePhase) private var scenePhase
    @State private var triedBiometrics = false

    @State private var password = ""
    @State private var recoveryKey = ""
    @State private var useRecovery = false
    @State private var message: String?
    @FocusState private var fieldFocused: Bool
    @State private var usePin = false
    @State private var pin = ""
    @State private var pinFeedback = PinPad.Feedback.none
    @State private var pinShake = 0

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let wait = vault.throttle.remaining(now: context.date)
            if usePin, showPin {
                pinEntry
            } else {
                passwordEntry(wait: wait)
            }
        }
        .task(id: scenePhase) {
            // Prompt once per appearance of the unlock screen, and only while the app is active:
            // a prompt during launch fails with "interaction not allowed".
            guard scenePhase == .active else { return }
            vault.refreshBiometricAvailability()
            guard showFaceID, vault.biometricAvailability == .available, !triedBiometrics else {
                // No Face ID prompt coming: PIN pad or keyboard right away.
                if !(showFaceID && vault.biometricAvailability == .available) { focusEntry() }
                return
            }
            triedBiometrics = true
            faceID()
        }
    }

    /// Number pad; the attempt starts with the sixth digit.
    private var pinEntry: some View {
        VStack(spacing: 20) {
            Spacer(minLength: 12)
            AppMark(size: 56)
            Text("Enter PIN")
                .font(.title2.weight(.bold))
            PinPad(pin: $pin, isDisabled: vault.isWorking, shake: pinShake, feedback: pinFeedback) { _ in
                submitPin()
            }
            HStack(spacing: 24) {
                if showFaceID {
                    Button("Face ID", systemImage: "faceid", action: faceID)
                        .disabled(vault.isWorking)
                }
                Button("Use master password") {
                    usePin = false
                    pin = ""
                    fieldFocused = true
                }
                .disabled(vault.isWorking)
            }
            .foregroundStyle(Theme.mint)
            Spacer(minLength: 12)
        }
        .padding(24)
    }

    private func passwordEntry(wait: TimeInterval) -> some View {
            VStack(spacing: 24) {
                Spacer()
                AppMark()
                Text(useRecovery ? "Use recovery key" : "Unlock your vault")
                    .font(.title.weight(.bold))

                if useRecovery {
                    PasswordInput(
                        title: "Recovery key", text: $recoveryKey, secure: false, onSubmit: submit,
                        focus: $fieldFocused)
                } else {
                    PasswordInput(title: "Master password", text: $password, onSubmit: submit, focus: $fieldFocused)
                }

                if let notice = vault.lockNotice {
                    Text(notice).font(.footnote).foregroundStyle(.secondary)
                }

                if wait > 0 {
                    Notice("Too many attempts. Try again in \(Int(wait.rounded(.up))) seconds.", tone: .warning)
                } else if let text = message ?? (showFaceIDBlocked ? String(localized: Self.pausedText) : nil) {
                    Notice(verbatim: text)
                }

                Button(action: submit) {
                    Group {
                        if vault.isWorking {
                            ProgressView()
                        } else {
                            Text(useRecovery ? "Unlock with recovery key" : "Unlock")
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .foregroundStyle(Theme.onAccent)
                .controlSize(.large)
                .disabled(vault.isWorking || wait > 0 || input.isEmpty)

                if showFaceID, let text = VaultService.message(for: vault.biometricAvailability) {
                    Notice(verbatim: text, tone: .warning)
                        .multilineTextAlignment(.center)
                } else if showFaceID {
                    Button(action: faceID) {
                        Label("Unlock with Face ID", systemImage: "faceid")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glass)
                    .controlSize(.large)
                    .disabled(vault.isWorking)
                    .accessibilityLabel("Unlock with Face ID")
                }

                if showPin {
                    Button("Use PIN") {
                        message = nil
                        usePin = true
                    }
                    .foregroundStyle(Theme.mint)
                    .disabled(vault.isWorking)
                }

                Spacer()
                // Rarely needed: small and at the bottom.
                Button(useRecovery ? "Use password" : "Use recovery key") {
                    useRecovery.toggle()
                    password = ""
                    recoveryKey = ""
                    message = nil
                    fieldFocused = true
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
                .disabled(vault.isWorking)
            }
            .padding(24)
    }

    private var showPin: Bool {
        vault.pinEnabled && entitlements.isUnlocked(.biometricUnlock) && !vault.pinPaused && !useRecovery
    }

    /// PIN pad when PIN unlock is on, otherwise the password keyboard.
    private func focusEntry() {
        #if DEBUG
            // Store screenshots show the screen without the keyboard.
            if DemoMode.isRequested { return }
        #endif
        if showPin {
            usePin = true
        } else {
            fieldFocused = true
        }
    }

    private func submitPin() {
        guard UnlockPin.isValid(pin) else { return }
        // The dots stay full while the PIN is checked.
        let value = pin
        message = nil
        Task {
            let result = await vault.unlock(pin: value) {
                pinFeedback = .accepted
                try? await Task.sleep(for: .milliseconds(350))
            }
            if case .unlocked = result { return }
            pinShake += 1
            // Let the shake play before the password field takes over.
            try? await Task.sleep(for: .milliseconds(450))
            pin = ""
            // A wrong PIN turned PIN unlock off; the password is the way in now.
            usePin = false
            handle(result)
            fieldFocused = true
        }
    }

    private var showFaceID: Bool {
        vault.biometricEnabled && entitlements.isUnlocked(.biometricUnlock) && !useRecovery
            && !vault.biometricBlocked
    }

    static let pausedText: String.LocalizationValue = "Face ID is paused. Enter your master password to use Face ID again."

    private var showFaceIDBlocked: Bool {
        vault.biometricEnabled && entitlements.isUnlocked(.biometricUnlock) && vault.biometricBlocked
    }

    private func faceID() {
        message = nil
        Task {
            let result = await vault.unlockWithBiometrics()
            vault.refreshBiometricAvailability()
            // Availability problems (lockout, not enrolled, …) are already shown below the button.
            if case .unlocked = result { return }
            focusEntry()
            if case .failed(let text) = result, text == VaultService.message(for: vault.biometricAvailability) {
                return
            }
            handle(result)
        }
    }

    private func handle(_ result: UnlockAttempt) {
        switch result {
        case .unlocked, .cancelled: break
        case .wrongPassword: message = String(localized: "Wrong password.")
        case .failed(let text): message = text
        }
    }

    private var input: String { useRecovery ? recoveryKey : password }

    private func submit() {
        guard !input.isEmpty else { return }
        let usingRecovery = useRecovery
        let value = input
        password = ""
        recoveryKey = ""
        message = nil
        Task {
            let result = usingRecovery
                ? await vault.unlock(recoveryKey: value)
                : await vault.unlock(password: value)
            handle(result)
        }
    }
}

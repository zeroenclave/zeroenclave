import SwiftUI

struct CreatePasswordView: View {
    let vault: VaultService
    let onCreated: () -> Void

    @State private var password = ""
    @State private var confirmation = ""
    @State private var errorMessage: String?
    private let policy = PasswordPolicy()

    var body: some View {
        let evaluation = policy.evaluate(password)
        let requirements = PasswordRequirements(password: password, confirmation: confirmation, policy: policy)
        let canContinue = policy.canContinue(password: password, confirmation: confirmation)
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Step 1 of 2")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text("Create a master password")
                        .font(.title.weight(.bold))
                }
                Text("It encrypts everything in your vault.")
                    .foregroundStyle(.secondary)

                VStack(alignment: .leading, spacing: 6) {
                    Label("Why a strong password?", systemImage: "info.circle.fill")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(Theme.mint)
                    Text("A copy of the vault, for example a backup, can be attacked offline with unlimited attempts. A long password makes this impractical.")
                    Text("Tip: four or five random words are strong and easy to remember.")
                        .foregroundStyle(.secondary)
                }
                .font(.footnote)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.fill.tertiary, in: .rect(cornerRadius: 16))

                PasswordInput(title: "Master password", text: $password, contentType: .newPassword)
                StrengthMeter(evaluation: evaluation, showsLength: false)

                PasswordInput(title: "Repeat password", text: $confirmation, contentType: .newPassword)

                if !password.isEmpty || !confirmation.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        requirement("At least \(PasswordPolicy.minLength) characters", met: requirements.hasMinLength)
                        requirement("Strong enough", met: requirements.isStrongEnough)
                        requirement("Both passwords match", met: requirements.matches)
                    }
                    .transition(.opacity.combined(with: .move(edge: .top)))
                }

                Label {
                    Text("This password cannot be reset. Without it and the recovery key, the data is lost.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                .font(.footnote)

                if let errorMessage {
                    Notice(verbatim: errorMessage)
                }

                Button(action: submit) {
                    Group {
                        if vault.isWorking {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text(vault.isCalibrating ? "Preparing…" : "Creating vault…")
                            }
                        } else {
                            Text("Continue")
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .foregroundStyle(Theme.onAccent)
                .controlSize(.large)
                .disabled(!canContinue || vault.isWorking)
            }
            .padding(24)
        }
        .scrollDismissesKeyboard(.interactively)
        .animation(.default, value: password.isEmpty && confirmation.isEmpty)
    }

    private func requirement(_ text: LocalizedStringKey, met: Bool) -> some View {
        Label {
            Text(text).foregroundStyle(met ? Theme.ink : Color.secondary)
        } icon: {
            Image(systemName: met ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(met ? Theme.mint : Color.secondary)
        }
        .font(.footnote)
        .accessibilityElement(children: .combine)
        .accessibilityValue(met ? Text("Done") : Text("Not done"))
    }

    private func submit() {
        let value = password
        password = ""
        confirmation = ""
        errorMessage = nil
        Task {
            errorMessage = await vault.createVault(password: value)
            if errorMessage == nil { onCreated() }
        }
    }
}

import SwiftUI

/// Gate for the self-destruct setup form: the password becomes the master password of the new vault,
/// so it must pass the same rule as onboarding and password change.
struct DuressSetupGate {
    var policy = PasswordPolicy()

    func canSet(
        understood: Bool, password: String, confirmation: String, isWorking: Bool, entitled: Bool
    ) -> Bool {
        understood && !isWorking && entitled
            && policy.canContinue(password: password, confirmation: confirmation)
    }
}

/// Sets or disables the panic password; lists the limits before anything is changed.
struct DuressView: View {
    /// Follows Dynamic Type instead of a fixed point size.
    @ScaledMetric(relativeTo: .largeTitle) private var iconSize: CGFloat = 40

    let vault: VaultService

    @Environment(Entitlements.self) private var entitlements
    @State private var premiumGate = PremiumGate()
    @State private var understood = false
    @State private var flow: DuressSetupFlow.Mode?

    var body: some View {
        Form {
            Section {
                VStack(spacing: 8) {
                    Image(systemName: "flame.fill")
                        .font(.system(size: iconSize))
                        .foregroundStyle(.orange)
                        .accessibilityHidden(true)
                    Text("A second password that destroys your vault.")
                        .font(.headline)
                        .multilineTextAlignment(.center)
                    PremiumBadge()
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            }
            Section("How it works") {
                step(1, "You set a second password, different from your master password.")
                step(2, "If someone forces you to unlock Zero Enclave, enter this password instead.")
                step(3, "The vault on this device is destroyed and an empty vault opens that looks like a new one.")
                Text("Afterwards this password is the master password of the empty vault. Create a new recovery key in Security.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Section("Limits") {
                limit("It only affects this device. Backups and copies elsewhere keep your data.")
                limit("Destroying data on demand can be an offence in some situations, for example when it is evidence. Know your legal situation.")
                limit("Your recovery key becomes useless once the vault is destroyed.")
                limit("The panic password must differ from your master password. Changing the master password turns it off.")
            }
            if entitlements.isUnlocked(.duressPassword) {
                Section {
                    Toggle("I understand these limits", isOn: $understood)
                    Button(vault.duressEnabled ? "Change panic password" : "Set up panic password") {
                        flow = .set
                    }
                    .disabled(!understood || vault.isWorking)
                }
            } else {
                Section {
                    Button {
                        premiumGate.require(.duressPassword)
                    } label: {
                        Text("Set up with Premium").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.glassProminent)
                    .foregroundStyle(Theme.onAccent)
                    .controlSize(.large)
                    .listRowBackground(Color.clear)
                }
            }
            if vault.duressEnabled {
                Section {
                    Button("Turn off", role: .destructive) { flow = .disable }
                        .disabled(vault.isWorking || !entitlements.isUnlocked(.duressPassword))
                }
            }
        }
        .navigationTitle("Panic password")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $flow) { mode in
            DuressSetupFlow(vault: vault, mode: mode) {
                flow = nil
                understood = false
            }
            .privacyCover()
        }
        .sheet(isPresented: $premiumGate.isPresentingRequired) {
            PremiumRequiredSheet(feature: premiumGate.requested)
                .privacyCover()
        }
    }

    private func step(_ number: Int, _ text: LocalizedStringKey) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text("\(number)")
                .font(.subheadline.weight(.bold))
                .foregroundStyle(Theme.mint)
                .frame(width: 20)
            Text(text)
        }
        .accessibilityElement(children: .combine)
    }

    private func limit(_ text: LocalizedStringKey) -> some View {
        Label {
            Text(text)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        }
        .font(.subheadline)
    }
}

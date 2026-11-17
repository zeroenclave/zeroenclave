import SwiftUI

/// Face ID, PIN, master password, recovery key, auto-lock and panic password.
struct SecuritySettingsView: View {
    let vault: VaultService

    @Environment(Entitlements.self) private var entitlements
    @State private var gate = PremiumGate()
    @State private var showEnableFaceID = false
    @State private var showEnablePin = false
    @State private var showChangePassword = false
    @State private var showRotateRecovery = false

    var body: some View {
        Form {
            faceIDSection

            Section {
                Button {
                    showChangePassword = true
                } label: {
                    sheetRow("Change master password", systemName: "key.fill")
                }
                .foregroundStyle(.primary)
                Button {
                    showRotateRecovery = true
                } label: {
                    sheetRow("Show new recovery key", systemName: "lifepreserver.fill")
                }
                .foregroundStyle(.primary)
            } footer: {
                Text("A new recovery key replaces the old one. The old key stops working.")
            }

            Section {
                Picker(
                    selection: Binding(
                        get: { vault.inactivityMinutes }, set: { vault.setInactivityMinutes($0) })
                ) {
                    ForEach(VaultService.inactivityChoices, id: \.self) { minutes in
                        Text(minutes == 1 ? "1 minute" : "\(minutes) minutes").tag(minutes)
                    }
                } label: {
                    SettingsLabel(title: "Lock after", systemName: "lock.fill")
                }
            } footer: {
                Text("Zero Enclave locks the vault immediately when you leave the app.")
            }

            Section {
                NavigationLink(value: SettingsView.Route.duress) {
                    HStack(spacing: 14) {
                        SettingsIcon(systemName: "flame.fill", tint: .red)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text("Panic password")
                                PremiumBadge()
                            }
                            Text("Wipes the vault if you are forced to unlock it.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(vault.duressEnabled ? "On" : "Off").foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Security")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $gate.isPresentingRequired) {
            PremiumRequiredSheet(feature: gate.requested)
                .privacyCover()
        }
        .sheet(isPresented: $showEnableFaceID) {
            EnableFaceIDView(vault: vault) { showEnableFaceID = false }
                .privacyCover()
        }
        .sheet(isPresented: $showEnablePin) {
            EnablePinView(vault: vault) { showEnablePin = false }
                .privacyCover()
        }
        .sheet(isPresented: $showChangePassword) {
            ChangePasswordFlow(vault: vault) { showChangePassword = false }
                .privacyCover()
        }
        .sheet(isPresented: $showRotateRecovery) {
            RotateRecoveryFlow(vault: vault) { showRotateRecovery = false }
                .privacyCover()
        }
        .onAppear { vault.refreshBiometricAvailability() }
    }

    private var faceIDSection: some View {
        Section {
            Toggle(isOn: Binding(get: { vault.biometricEnabled }, set: setFaceID)) {
                HStack(spacing: 14) {
                    SettingsIcon(systemName: "faceid")
                    Text("Unlock with Face ID")
                    PremiumBadge()
                }
            }
            .tint(Theme.mint)
            .disabled(vault.isWorking)
            Toggle(isOn: Binding(get: { vault.pinEnabled }, set: setPin)) {
                HStack(spacing: 14) {
                    SettingsIcon(systemName: "circle.grid.3x3.fill")
                    Text("Unlock with PIN")
                    PremiumBadge()
                }
            }
            .tint(Theme.mint)
            .disabled(vault.isWorking)
        } footer: {
            // Only a problem is worth a line; the toggle explains itself.
            if let text = VaultService.message(for: vault.biometricAvailability) {
                Text(text)
            } else if vault.biometricBlocked {
                Text("Face ID is paused. Enter your master password to use Face ID again.")
            }
        }
    }

    private func setPin(_ on: Bool) {
        if on {
            gate.perform(.biometricUnlock, entitlements: entitlements) { showEnablePin = true }
        } else {
            Task { _ = await vault.disablePin() }
        }
    }

    private func setFaceID(_ on: Bool) {
        if on {
            gate.perform(.biometricUnlock, entitlements: entitlements) { showEnableFaceID = true }
        } else {
            Task { _ = await vault.disableBiometrics() }
        }
    }

    /// Row that opens a step flow in a sheet; looks like a navigation row.
    private func sheetRow(_ title: LocalizedStringKey, systemName: String) -> some View {
        HStack {
            SettingsLabel(title: title, systemName: systemName)
            Spacer()
            Image(systemName: "chevron.right")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.tertiary)
        }
        .contentShape(.rect)
    }
}

import SwiftUI

/// Shown when the core opened the vault read-only because its files do not match the local
/// state (possible rollback). The owner can keep it read-only or confirm the files as they are.
struct ReadOnlyNoticeSheet: View {
    let vault: VaultService

    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var errorMessage: String?
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    FlowHeader(
                        icon: "exclamationmark.shield.fill", title: Text("Vault files changed"),
                        subtitle: String(
                            localized: "Zero Enclave found vault files on this device that differ from what it recorded. Older files may have been put back, for example from a copy."
                        ))
                        .frame(maxWidth: .infinity)
                }
                Section {
                    Text("Until you confirm, the vault is read-only. You can view photos and export a backup, but not change anything.")
                    Text("Confirm only if you restored these files yourself.")
                        .foregroundStyle(.secondary)
                }
                Section {
                    SecureField("Master password", text: $password)
                        .masterPasswordStyle()
                        .textContentType(.password)
                        .privacySensitive()
                        .focused($focused)
                    if let errorMessage {
                        Notice(verbatim: errorMessage)
                    }
                }
                Section {
                    Button("Confirm current files", action: confirm)
                        .disabled(password.isEmpty || vault.isWorking)
                    Button("Keep read-only") { dismiss() }
                }
            }
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .navigationBarTitleDisplayMode(.inline)
        }
        .interactiveDismissDisabled(vault.isWorking)
        .autoFocus($focused)
    }

    private func confirm() {
        let value = password
        errorMessage = nil
        Task {
            errorMessage = await vault.acceptCurrentState(password: value)
            if errorMessage == nil { dismiss() }
        }
    }
}

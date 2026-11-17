import SwiftUI

/// Confirmation sheet for erasing the vault: master password plus the typed confirmation word.
struct EraseVaultView: View {
    let vault: VaultService
    let onErased: () -> Void
    let onCancel: () -> Void

    /// "ERASE" in English, "LÖSCHEN" in German.
    static var confirmationWord: String { String(localized: "ERASE", comment: "Word typed to confirm erasing") }

    /// The button stays disabled until both fields are filled in.
    static func canErase(password: String, word: String) -> Bool {
        !password.isEmpty && word == confirmationWord
    }

    @State private var password = ""
    @State private var word = ""
    @State private var message: String?
    @State private var confirming = false
    @FocusState private var passwordFocused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ConsequenceList(items: [
                        Consequence(systemImage: "trash.fill", text: "All photos and videos are deleted"),
                        Consequence(
                            systemImage: "arrow.uturn.backward.circle.fill", text: "Cannot be undone",
                            tone: .warning),
                        Consequence(systemImage: "key.slash.fill", text: "The recovery key stops working"),
                        Consequence(
                            systemImage: "checkmark.shield.fill", text: "Exported backups are kept", tone: .safe),
                    ])
                }
                Section {
                    SecureField("Master password", text: $password)
                        .masterPasswordStyle()
                        .textContentType(.password)
                        .privacySensitive()
                        .focused($passwordFocused)
                    TextField("Type \(Self.confirmationWord) to confirm", text: $word)
                        .multilineTextAlignment(.center)
                        .textInputAutocapitalization(.characters)
                }
                if let message {
                    Section { Notice(verbatim: message) }
                }
                Section {
                    Button("Erase vault", role: .destructive) { confirming = true }
                        .disabled(!Self.canErase(password: password, word: word) || vault.isWorking)
                }
            }
            .autocorrectionDisabled()
            .confirmSheet(
                isPresented: $confirming, systemImage: "exclamationmark.triangle.fill",
                title: "Are you sure?",
                message: "All photos and videos in this vault will be deleted for good.",
                actions: [ConfirmAction(title: "Erase vault", role: .destructive, action: erase)])
            .autoFocus($passwordFocused)
            .navigationTitle("Erase vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel).disabled(vault.isWorking)
                }
            }
        }
        .interactiveDismissDisabled(vault.isWorking)
    }

    private func erase() {
        let value = password
        password = ""
        message = nil
        Task {
            if let failure = await vault.eraseVault(password: value) {
                message = failure
            } else {
                onErased()
            }
        }
    }
}

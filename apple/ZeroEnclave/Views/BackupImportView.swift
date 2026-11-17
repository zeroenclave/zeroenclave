import SwiftUI
import ZeroEnclaveCore

/// Asks for the backup's password or recovery key and imports the chosen file.
struct BackupImportView: View {
    enum Mode {
        /// Merge into the open vault.
        case merge
        /// Restore into the empty vault directory of a fresh install.
        case restore
        /// Replace the open vault; needs the master password and a typed confirmation.
        case replace
    }

    let vault: VaultService
    let url: URL
    let onClose: () -> Void

    @State private var mode: Mode
    @State private var useRecovery = false
    @State private var secret = ""
    @State private var isConfirming = false
    @State private var currentPassword = ""
    @State private var word = ""
    @State private var isRunning = false
    @State private var message: String?
    /// Keyboard for the backup secret, then for the current password on the confirmation step.
    @FocusState private var focused: Bool
    @State private var offersReplace = false
    @State private var outcome: ImportOutcome?

    init(vault: VaultService, url: URL, mode: Mode, onClose: @escaping () -> Void) {
        self.vault = vault
        self.url = url
        self.onClose = onClose
        _mode = State(initialValue: mode)
    }

    var body: some View {
        NavigationStack {
            Form {
                if let outcome {
                    Section {
                        Text(summary(outcome))
                        Text(VaultService.duressResetNotice)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } else if isConfirming {
                    confirmationSections
                } else {
                    secretSections
                }
            }
            .autocorrectionDisabled()
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(outcome == nil ? "Cancel" : "Done", action: onClose).disabled(isRunning)
                }
            }
        }
        .interactiveDismissDisabled(isRunning)
        .presentationDetents([.medium, .large])
        .autoFocus($focused, id: "\(isConfirming)-\(useRecovery)")
    }

    private var title: LocalizedStringKey {
        switch mode {
        case .merge: "Import backup"
        case .restore: "Restore from backup"
        case .replace: "Replace vault"
        }
    }

    @ViewBuilder private var secretSections: some View {
        Section {
            Picker("Backup secret", selection: $useRecovery) {
                Text("Password").tag(false)
                Text("Recovery key").tag(true)
            }
            .pickerStyle(.segmented)
            .disabled(isRunning)
            if useRecovery {
                TextField("Recovery key", text: $secret)
                    .multilineTextAlignment(.center)
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.characters)
                    .privacySensitive()
                    .focused($focused)
            } else {
                SecureField("Backup password", text: $secret)
                    .masterPasswordStyle()
                    .textContentType(.password)
                    .privacySensitive()
                    .focused($focused)
            }
        } footer: {
            Text("Enter the password or recovery key the vault had when the backup was made.")
        }
        if let text = message {
            Section {
                Notice(verbatim: text)
                if offersReplace {
                    Button("Replace this vault with the backup", action: switchToReplace)
                }
            }
        }
        Section {
            Button {
                if mode == .replace { proceed() } else { run() }
            } label: {
                if isRunning {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Importing…")
                    }
                } else {
                    switch mode {
                    case .merge: Text("Import backup")
                    case .restore: Text("Restore backup")
                    case .replace: Text("Continue")
                    }
                }
            }
            .disabled(secret.isEmpty || isRunning)
        }
    }

    @ViewBuilder private var confirmationSections: some View {
        Section {
            ConsequenceList(items: [
                Consequence(systemImage: "trash.fill", text: "The current vault is replaced by the backup"),
                Consequence(
                    systemImage: "arrow.uturn.backward.circle.fill", text: "Cannot be undone", tone: .warning),
                Consequence(systemImage: "key.slash.fill", text: "The current recovery key stops working"),
            ])
        }
        Section {
            SecureField("Current master password", text: $currentPassword)
                .masterPasswordStyle()
                .textContentType(.password)
                .privacySensitive()
                .focused($focused)
            TextField("Type \(EraseVaultView.confirmationWord) to confirm", text: $word)
                .multilineTextAlignment(.center)
                .textInputAutocapitalization(.characters)
        }
        if let message {
            Section { Notice(verbatim: message) }
        }
        Section {
            Button(role: .destructive, action: replace) {
                if isRunning {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Replacing…")
                    }
                } else {
                    Text("Replace vault")
                }
            }
            .disabled(!EraseVaultView.canErase(password: currentPassword, word: word) || isRunning)
        }
    }

    private func summary(_ outcome: ImportOutcome) -> String {
        switch outcome {
        case .restored:
            String(localized: "Backup restored.")
        case .merged(let objects, _):
            objects == 0
                ? String(localized: "Nothing new in this backup.")
                : String(localized: "Added \(objects) files from the backup.")
        }
    }

    private func importSecret() -> ImportSecret {
        useRecovery
            ? .recoveryKey(recoveryKey: secret.trimmingCharacters(in: .whitespacesAndNewlines))
            : .password(password: secret)
    }

    /// A backup of another vault can only replace this one.
    private func switchToReplace() {
        message = nil
        offersReplace = false
        mode = .replace
    }

    /// Second step of replacing: the backup secret is kept until the final confirmation.
    private func proceed() {
        message = nil
        isConfirming = true
    }

    private func run() {
        let importSecret = importSecret()
        secret = ""
        message = nil
        offersReplace = false
        isRunning = true
        Task {
            defer { isRunning = false }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            switch mode {
            case .merge:
                switch await vault.importBackup(from: url, secret: importSecret) {
                case .success(let result): outcome = result
                case .failure(let failure):
                    message = failure.message
                    offersReplace = failure.isDifferentVault
                }
            case .restore:
                // On success the vault becomes locked and this sheet goes away with the welcome screen.
                message = await vault.restoreBackup(from: url, secret: importSecret)
            case .replace:
                break
            }
        }
    }

    private func replace() {
        let importSecret = importSecret()
        let password = currentPassword
        currentPassword = ""
        message = nil
        isRunning = true
        Task {
            defer { isRunning = false }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            // On success the vault is locked and this sheet goes away with the unlocked screen.
            if let failure = await vault.replaceFromBackup(currentPassword: password, url: url, secret: importSecret) {
                message = failure
                // The vault is untouched: let the user correct either secret.
                word = ""
                secret = ""
                isConfirming = false
            }
        }
    }
}

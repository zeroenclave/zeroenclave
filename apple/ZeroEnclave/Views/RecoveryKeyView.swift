import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct RecoveryKeyView: View {
    let recoveryKey: String
    /// Onboarding shows its step; a key rotation from Settings does not.
    var showsStep = true
    let onConfirmed: () -> Void

    /// The copied key is removed from the clipboard after this time.
    static let clipboardLifetime: TimeInterval = 120

    @State private var saved = false
    @State private var copied = false

    private var groups: [String] {
        recoveryKey.split(separator: "-").map(String.init)
    }

    /// Local only (no Universal Clipboard) and with an expiry, so the key does not linger.
    static func copyToClipboard(_ key: String, pasteboard: UIPasteboard = .general) {
        pasteboard.setItems(
            [[UTType.plainText.identifier: key]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(clipboardLifetime)])
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 4) {
                    if showsStep {
                        Text("Step 2 of 2")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Text("Your recovery key")
                        .font(.title.weight(.bold))
                }
                Text("If you forget the master password, only this key opens the vault. It is shown only once.")
                    .foregroundStyle(.secondary)

                LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 4), spacing: 12) {
                    ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                        Text(group)
                            .font(.system(.body, design: .monospaced).weight(.semibold))
                            .padding(.vertical, 4)
                            .frame(maxWidth: .infinity)
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity)
                .background(Theme.mint.opacity(0.12), in: .rect(cornerRadius: 20))
                .textSelection(.disabled)
                .privacySensitive()
                .accessibilityElement(children: .combine)

                Button(action: copy) {
                    Label(
                        copied ? "Copied" : "Copy recovery key",
                        systemImage: copied ? "checkmark" : "doc.on.doc"
                    )
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)

                Text("Save it in a password manager or write it down. The clipboard is cleared after 2 minutes.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                Toggle("I have saved my recovery key", isOn: $saved)
                    .font(.headline)
                    .tint(Theme.mint)

                Button(action: onConfirmed) {
                    Text("Continue").frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .foregroundStyle(Theme.onAccent)
                .controlSize(.large)
                .disabled(!saved)
            }
            .padding(24)
        }
    }

    private func copy() {
        Self.copyToClipboard(recoveryKey)
        // Stays visible; tapping again copies again.
        copied = true
    }
}

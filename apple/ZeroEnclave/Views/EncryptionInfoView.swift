import SwiftUI

/// Plain-language overview of the cryptography and on-device protections.
struct EncryptionInfoView: View {
    /// Follows Dynamic Type instead of a fixed point size.
    @ScaledMetric(relativeTo: .largeTitle) private var iconSize: CGFloat = 56

    var body: some View {
        List {
            Section {
                VStack(spacing: 12) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: iconSize))
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(Theme.mint)
                        .accessibilityHidden(true)
                    Text("Encrypted on your device")
                        .font(.title2.weight(.bold))
                    Text("The vault opens only with the master password or the recovery key.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .listRowBackground(Color.clear)
            }

            Section("Master password") {
                InfoRow(
                    icon: "key.fill", title: "Argon2id", value: "64 MiB",
                    detail: "Derives the key from the master password. Each attempt takes 64 MiB of memory and about one second, which slows down password guessing.")
            }

            Section("Keys") {
                InfoRow(
                    icon: "key.horizontal.fill", title: "Vault key", value: "256-bit",
                    detail: "Random key for all vault content. Stored only wrapped with AES-256-GCM.")
                InfoRow(
                    icon: "arrow.triangle.branch", title: "HKDF-SHA256", value: "RFC 5869",
                    detail: "Derives a separate subkey for each purpose (domain separation).")
                InfoRow(
                    icon: "lifepreserver.fill", title: "Recovery key", value: "256-bit",
                    detail: "Shown once at setup. Not stored by the app.")
            }

            Section("Photos and videos") {
                InfoRow(
                    icon: "photo.on.rectangle.angled", title: "AES-256-GCM", value: "NIST SP 800-38D",
                    detail: "Each file has its own random key and is encrypted in 1 MiB segments. Modification, reordering and truncation are detected.")
                InfoRow(
                    icon: "square.grid.2x2.fill", title: "Thumbnails and albums",
                    detail: "Thumbnails, album names, dates and file details are encrypted as well.")
            }

            Section("On your device") {
                InfoRow(
                    icon: "faceid", title: "Face ID",
                    detail: "Uses a key in the Secure Enclave, bound to the enrolled faces. No passcode fallback.")
                InfoRow(
                    icon: "circle.grid.3x3.fill", title: "PIN",
                    detail: "Works only together with a key in the Secure Enclave of this device. After one wrong PIN, the master password is required.")
                InfoRow(
                    icon: "lock.iphone", title: "iOS Data Protection",
                    detail: "Vault files cannot be read while the device is locked (Data Protection: Complete).")
                InfoRow(
                    icon: "eye.slash.fill", title: "Capture protection",
                    detail: "Screenshots, screen recordings and mirroring do not show vault content.")
                InfoRow(
                    icon: "wifi.slash", title: "No network access",
                    detail: "The app makes no network connections: no server, no account, no analytics.")
            }

            Section {
                InfoRow(
                    icon: "chevron.left.forwardslash.chevron.right", title: "Open Source", value: "GPLv3",
                    detail: "Cryptography is implemented in Rust with the RustCrypto libraries. Keys never leave the Rust core and are zeroed after use.")
            } header: {
                Text("Verifiable")
            } footer: {
                Text("All algorithms are published standards: RFC 9106, RFC 5869 and NIST SP 800-38D.")
            }
        }
        .navigationTitle("Encryption")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct InfoRow: View {
    let icon: String
    let title: LocalizedStringKey
    /// Technical identifier, shown verbatim.
    var value: String?
    let detail: LocalizedStringKey

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(Theme.mint)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(title).font(.body.weight(.semibold))
                    Spacer(minLength: 8)
                    if let value {
                        Text(verbatim: value)
                            .font(.footnote.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

#Preview {
    NavigationStack { EncryptionInfoView() }
}

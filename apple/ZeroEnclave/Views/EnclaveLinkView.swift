import SwiftUI

// Store builds ship only working features (App Review 2.1); the preview needs ZE_PREVIEW.
#if ZE_PREVIEW

/// Preview of Enclave Link, the encrypted sync. Same layout as the Premium page; nothing to buy yet.
struct EnclaveLinkView: View {
    private struct Item: Identifiable {
        let icon: String
        let title: LocalizedStringResource
        let detail: LocalizedStringResource
        var id: String { icon }
    }

    private static let sync: [Item] = [
        Item(icon: "icloud.fill", title: "iCloud Drive", detail: "Sync with your Apple Account. No extra account."),
        Item(icon: "externaldrive.connected.to.line.below.fill", title: "Google Drive and OneDrive", detail: "Use the cloud you already have."),
        Item(icon: "server.rack", title: "Own server", detail: "Nextcloud, WebDAV or your server with Docker or Linux."),
        Item(icon: "point.3.connected.trianglepath.dotted", title: "Device to device", detail: "Direct connection, without storage in between."),
    ]

    private static let principles: [Item] = [
        Item(icon: "eye.slash.fill", title: "What the cloud sees", detail: "No photos, names or albums. Only encrypted files."),
        Item(icon: "key.fill", title: "Your password stays here", detail: "The master password never leaves your device."),
        Item(icon: "iphone.gen3", title: "All your devices", detail: "Each device opens the vault with your master password."),
        Item(icon: "creditcard.fill", title: "One-time purchase", detail: "No subscription. Separate from Premium."),
    ]

    private let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
    @ScaledMetric(relativeTo: .largeTitle) private var iconSize: CGFloat = 56

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                hero
                endToEnd
                section("Sync options", items: Self.sync)
                section("How it works", items: Self.principles)
            }
            .padding()
            .frame(maxWidth: 520)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle(Text(verbatim: "Enclave Link"))
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) { callToAction }
        // A showcase page: the tab bar would crowd the call to action.
        .toolbar(.hidden, for: .tabBar)
    }

    private var hero: some View {
        ShowcaseHero(
            gradient: Theme.linkGradient,
            title: Text(verbatim: "Enclave Link"),
            subtitle: Text("End-to-end encrypted on all your devices"),
            badge: Label("Available soon", systemImage: "clock.fill")
        ) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: iconSize, weight: .semibold))
                .accessibilityHidden(true)
        }
        .revealOnAppear()
    }

    /// The core promise: the cloud holds the same ciphertext as the device.
    private var endToEnd: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "lock.shield.fill")
                .font(.title)
                .foregroundStyle(Theme.mint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text("End-to-end encrypted")
                    .font(.headline)
                Text("Zero Enclave encrypts everything on your device before it is uploaded. In the cloud, your vault is encrypted exactly as it is on your device.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Theme.mint.opacity(0.12), in: .rect(cornerRadius: 22))
        .overlay(RoundedRectangle(cornerRadius: 22).strokeBorder(Theme.mint.opacity(0.35), lineWidth: 0.5))
        .accessibilityElement(children: .combine)
        .revealOnAppear(order: 1)
    }

    private func section(_ title: LocalizedStringKey, items: [Item]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title3.bold())
            LazyVGrid(columns: columns, spacing: 12) {
                ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                    FeatureCard(icon: item.icon, title: item.title, detail: item.detail, tile: Theme.linkGradient)
                        .revealOnAppear(order: index + 2)
                }
            }
        }
    }

    private var callToAction: some View {
        VStack(spacing: 8) {
            // Nothing to buy yet: a status capsule instead of a disabled button.
            Label("Available soon", systemImage: "clock.fill")
                .font(.headline)
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity, minHeight: 50)
                .background(Theme.linkGradient, in: .capsule)
            Text("Enclave Link comes as an update. Your vault stays on your device until then.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(16)
        .frame(maxWidth: 520)
        .glassEffect(.regular, in: .rect(cornerRadius: 28))
        .padding(.horizontal)
        .padding(.bottom, 8)
    }
}
#endif

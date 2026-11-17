import SwiftUI

struct WelcomeView: View {
    let vault: VaultService

    @State private var showImporter = false
    @State private var importURL: URL?

    var body: some View {
        // Scrolls only when the content does not fit (small screens, large text sizes).
        GeometryReader { proxy in
            ScrollView {
                content.frame(minHeight: proxy.size.height)
            }
            .scrollBounceBehavior(.basedOnSize)
        }
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.zeroEnclaveBackup, .data]) {
            if case .success(let url) = $0 { importURL = url }
        }
        .sheet(isPresented: Binding(get: { importURL != nil }, set: { if !$0 { importURL = nil } })) {
            if let importURL {
                BackupImportView(vault: vault, url: importURL, mode: .restore) { self.importURL = nil }
                    .privacyCover()
            }
        }
    }

    private var content: some View {
        VStack(spacing: 32) {
            Spacer()
            AppMark()
            VStack(spacing: 8) {
                Text("Zero Enclave")
                    .font(.largeTitle.weight(.bold))
                Text("A private vault for your photos and videos.")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                // The claim stays English in every language.
                Text(verbatim: "Private by design.")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Theme.mint)
            }
            VStack(alignment: .leading, spacing: 20) {
                point("iphone", "Local only", "Your vault stays on your device. The app has no network access.")
                point("key.fill", "Zero Knowledge", "Keys are created and stored only on your device. Without your password, the data cannot be read.")
                point("chevron.left.forwardslash.chevron.right", "Open Source", "Source code under GPLv3, open for review.")
            }
            Spacer()
            Button {
                vault.beginOnboarding()
            } label: {
                Text("Get started").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .foregroundStyle(Theme.onAccent)
            .controlSize(.large)
            Button {
                showImporter = true
            } label: {
                Text("Restore from backup").frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
        }
        .padding(24)
    }

    private func point(_ symbol: String, _ title: LocalizedStringKey, _ text: LocalizedStringKey) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(Theme.mint)
                .frame(width: 32)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(text).font(.subheadline).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

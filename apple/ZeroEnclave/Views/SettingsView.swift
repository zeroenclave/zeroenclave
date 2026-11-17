import SwiftUI

/// Settings tab of the unlocked vault; the caller provides the navigation stack.
struct SettingsView: View {
    let vault: VaultService

    /// Every page pushed from Settings. One value-based destination: mixing link styles in the
    /// shared tab stack popped pages right after they were pushed.
    enum Route: Hashable {
        case security, encryption, backup, about, premium, duress
        #if ZE_PREVIEW
        case link
        #endif
    }

    @Environment(Entitlements.self) private var entitlements

    @State private var gate = PremiumGate()
    @State private var showErase = false
    @State private var confirmReplace = false
    @State private var showReplacePicker = false
    @State private var replaceURL: URL?
    @State private var appIcon = AppIconChoice.current
    @State private var appIconFailed = false

    var body: some View {
        Form {
            securitySection
            premiumBanner
            #if ZE_PREVIEW
            linkBanner
            #endif
            appIconSection
            aboutSection
            dangerSection
        }
        .sheet(isPresented: $gate.isPresentingRequired) {
            PremiumRequiredSheet(feature: gate.requested)
                .privacyCover()
        }
        .navigationDestination(for: Route.self) { route in
            switch route {
            case .premium: PremiumView()
            #if ZE_PREVIEW
            case .link: EnclaveLinkView()
            #endif
            case .duress: DuressView(vault: vault)
            case .encryption: EncryptionInfoView()
            case .security: SecuritySettingsView(vault: vault)
            case .backup: BackupSettingsView(vault: vault)
            case .about: AboutView()
            }
        }
        .sheet(isPresented: $showErase) {
            EraseVaultView(
                vault: vault,
                onErased: {
                    showErase = false
                    entitlements.reload()
                },
                onCancel: { showErase = false }
            )
            .privacyCover()
        }
    }

    private var securitySection: some View {
        Section {
            NavigationLink(value: Route.security) {
                SettingsLabel(title: "Security", systemName: "lock.shield.fill")
            }
            NavigationLink(value: Route.backup) {
                SettingsLabel(title: "Backup", systemName: "externaldrive.fill")
            }
        }
    }

    private var premiumBanner: some View {
        Section {
            // Hidden link keeps the custom chevron on the gradient instead of the system one.
            ZStack {
                NavigationLink(value: Route.premium) { EmptyView() }.opacity(0)
                HStack(spacing: 12) {
                    Image(systemName: "sparkles")
                        .font(.title2)
                        .frame(width: Self.bannerIconWidth)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Zero Enclave Premium").font(.headline)
                        Text(
                            entitlements.preReleaseActive
                                ? LocalizedStringKey("Active")
                                : entitlements.preReleaseExpired
                                    ? LocalizedStringKey("Trial ended") : LocalizedStringKey("Early Bird: 6 months free")
                        )
                            .font(.subheadline)
                            .opacity(0.85)
                    }
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.footnote.weight(.semibold))
                        .opacity(0.7)
                        .accessibilityHidden(true)
                }
                .foregroundStyle(.white)
                .padding(.vertical, 6)
            }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isButton)
            .listRowBackground(Theme.premiumGradient)
        }
        .listSectionSpacing(Self.bannerSpacing)
    }

    /// Icon column and gap shared by the Premium and Enclave Link banners.
    private static let bannerIconWidth: CGFloat = 32
    private static let bannerSpacing: CGFloat = 12

    #if ZE_PREVIEW
    /// Enclave Link is a separate purchase; announced in preview builds until sync ships.
    private var linkBanner: some View {
        Section {
            ZStack {
            NavigationLink(value: Route.link) { EmptyView() }.opacity(0)
            HStack(spacing: 12) {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.title2)
                    .frame(width: Self.bannerIconWidth)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(verbatim: "Enclave Link").font(.headline)
                        Text("Available soon")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(.white.opacity(0.2), in: .capsule)
                    }
                    Text("Encrypted on all your devices")
                        .font(.subheadline)
                        .opacity(0.85)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.footnote.weight(.semibold))
                    .opacity(0.7)
                    .accessibilityHidden(true)
            }
            .foregroundStyle(.white)
            .padding(.vertical, 6)
            }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isButton)
            .listRowBackground(Theme.linkGradient)
        }
    }
    #endif

    private var appIconSection: some View {
        Section("App Icon") {
            HStack(spacing: 28) {
                ForEach(AppIconChoice.allCases) { choice in
                    Button { selectIcon(choice) } label: {
                        VStack(spacing: 8) {
                            Image(choice.logoName)
                                .resizable()
                                .interpolation(.high)
                                .scaledToFit()
                                .frame(width: 64, height: 64)
                                .overlay {
                                    if choice == appIcon {
                                        RoundedRectangle(cornerRadius: 20)
                                            .stroke(Theme.mint, lineWidth: 3)
                                            .padding(-5)
                                    }
                                }
                            HStack(spacing: 4) {
                                Text(choice.title).font(.footnote)
                                if choice.isPremium { PremiumBadge() }
                            }
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(choice == appIcon ? .isSelected : [])
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
        .alert("The app icon could not be changed.", isPresented: $appIconFailed) {
            Button("OK", role: .cancel) {}
        }
    }

    private func selectIcon(_ choice: AppIconChoice) {
        guard choice != appIcon else { return }
        let apply = {
            Task {
                do {
                    try await UIApplication.shared.setAlternateIconName(choice.alternateName)
                    appIcon = choice
                } catch {
                    appIconFailed = true
                }
            }
        }
        if choice.isPremium {
            gate.perform(.themes, entitlements: entitlements) { apply() }
        } else {
            apply()
        }
    }

    private var dangerSection: some View {
        Section("Danger Zone") {
            Button("Replace vault with a backup", role: .destructive) { confirmReplace = true }
            Button("Erase vault", role: .destructive) { showErase = true }
        }
        // First warning before the file is picked; the sheet then asks for the password and ERASE.
        .confirmSheet(
            isPresented: $confirmReplace, systemImage: "exclamationmark.triangle.fill",
            title: "Replace this vault?",
            message: "All photos and videos in this vault are deleted and replaced by the backup.",
            actions: [
                ConfirmAction(title: "Choose backup", role: .destructive) { showReplacePicker = true }
            ])
        .fileImporter(isPresented: $showReplacePicker, allowedContentTypes: [.zeroEnclaveBackup, .data]) { result in
            if case .success(let url) = result { replaceURL = url }
        }
        .sheet(isPresented: Binding(get: { replaceURL != nil }, set: { if !$0 { replaceURL = nil } })) {
            if let replaceURL {
                BackupImportView(vault: vault, url: replaceURL, mode: .replace) { self.replaceURL = nil }
                    .privacyCover()
            }
        }
    }

    /// Background information: how the encryption works and who makes the app.
    private var aboutSection: some View {
        Section {
            NavigationLink(value: Route.encryption) {
                SettingsLabel(title: "Encryption", systemName: "key.horizontal.fill", tint: .gray)
            }
            NavigationLink(value: Route.about) {
                SettingsLabel(title: "About Zero Enclave", systemName: "info", tint: .gray)
            }
        }
    }
}

import SwiftUI

/// Premium sales page: what is included, what is coming (preview builds only) and what stays free.
struct PremiumView: View {
    /// Feature that asked for premium; its card is emphasized.
    var highlight: Feature?

    @Environment(Entitlements.self) private var entitlements

    private static let available: [Feature] = [
        .albums, .biometricUnlock, .backupExport, .duressPassword, .trashRestore, .themes,
    ]
    private static let upcoming: [Feature] = [.bulkExport, .multipleVaults, .intruderAlert]
    private static let free: [LocalizedStringKey] = [
        "Unlimited encrypted photos and videos",
        "Restore backups",
        "Export single photos",
        "Import and camera",
        "No ads, no tracking",
    ]

    private let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    hero
                    if let highlight {
                        Text("\"\(String(localized: highlight.title))\" is part of Premium.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity)
                            .multilineTextAlignment(.center)
                    }
                    section("Included", features: Self.available, soon: false)
                    #if ZE_PREVIEW
                    section("Coming soon", features: Self.upcoming, soon: true)
                    #endif
                    freeSection
                }
                .padding()
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
            .task {
                guard let highlight else { return }
                try? await Task.sleep(for: .milliseconds(300))
                withAnimation { proxy.scrollTo(highlight, anchor: .center) }
            }
        }
        .navigationTitle("Premium")
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) { callToAction }
        // A showcase page: the tab bar would crowd the call to action.
        .toolbar(.hidden, for: .tabBar)
    }

    private var hero: some View {
        ShowcaseHero(
            gradient: Theme.premiumGradient,
            title: Text(verbatim: "Zero Enclave Premium"),
            subtitle: Text("Early Bird: Premium free for 6 months after download. No subscription."),
            badge: Label {
                statusText
            } icon: {
                Image(systemName: entitlements.preReleaseActive ? "checkmark.seal.fill" : "gift.fill")
            }
        ) {
            AppMark(size: 80)
        }
        .revealOnAppear()
    }

    private func section(_ title: LocalizedStringKey, features: [Feature], soon: Bool) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title3.bold())
            LazyVGrid(columns: columns, spacing: 12) {
                ForEach(Array(features.enumerated()), id: \.element) { index, feature in
                    FeatureCard(feature: feature, soon: soon, highlighted: feature == highlight)
                        .id(feature)
                        .revealOnAppear(order: index + 1)
                }
            }
        }
    }

    private var freeSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Always free")
                .font(.title3.bold())
            VStack(alignment: .leading, spacing: 12) {
                ForEach(Self.free.indices, id: \.self) { index in
                    Label {
                        Text(Self.free[index])
                    } icon: {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.mint)
                    }
                    .font(.subheadline)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(.fill.tertiary, in: .rect(cornerRadius: 20))
        }
    }

    /// "Active until …", "Trial ended" or "Early Bird".
    private var statusText: Text {
        if entitlements.preReleaseActive, let end = entitlements.preReleaseExpiry {
            return Text("Active until \(end.formatted(date: .long, time: .omitted))")
        }
        return entitlements.preReleaseExpired ? Text("Trial ended") : Text("Early Bird")
    }

    /// Before activation: the end of the free window if Apple's download date is known.
    private var trialNote: Text {
        if let end = entitlements.preReleaseExpiry {
            return Text("Free until \(end.formatted(date: .long, time: .omitted)), without a subscription.")
        }
        return Text("Free and without a subscription: 6 months for Early Birds.")
    }

    private var callToAction: some View {
        VStack(spacing: 8) {
            if entitlements.preReleaseActive {
                Label("Premium is active", systemImage: "checkmark.seal.fill")
                    .font(.headline)
                    .foregroundStyle(Theme.mint)
                    .padding(.vertical, 4)
                statusText
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else if entitlements.preReleaseExpired {
                Label("Trial ended", systemImage: "clock.badge.checkmark")
                    .font(.headline)
                    .padding(.vertical, 4)
                Text("Premium features are off. Your albums and photos stay visible.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            } else {
                Button {
                    entitlements.activatePreRelease()
                } label: {
                    Label("Activate Premium", systemImage: "sparkles")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .foregroundStyle(Theme.onAccent)
                .controlSize(.large)
                trialNote
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(16)
        .frame(maxWidth: 520)
        .glassEffect(.regular, in: .rect(cornerRadius: 28))
        .padding(.horizontal)
        .padding(.bottom, 8)
    }
}

extension Feature {
    /// Name on the premium page.
    var title: LocalizedStringResource {
        switch self {
        case .duressPassword: "Panic password"
        case .biometricUnlock: "Face ID and PIN"
        case .albums: "Albums"
        case .backupExport: "Encrypted backup"
        case .bulkExport: "Bulk export"
        case .multipleVaults: "Multiple vaults"
        case .intruderAlert: "Intruder alert"
        case .themes: "Themes & icons"
        case .sync: "Sync"
        case .trashRestore: "Restore from Trash"
        }
    }

    /// One-line description on the premium page.
    var detail: LocalizedStringResource {
        switch self {
        case .duressPassword: "Wipes the vault under pressure."
        case .biometricUnlock: "Unlock without the master password."
        case .albums: "Organize and hide photos behind a code."
        case .backupExport: "The whole vault in one encrypted file."
        case .bulkExport: "Export many items at once."
        case .multipleVaults: "Keep separate vaults apart."
        case .intruderAlert: "Spot failed unlock attempts."
        case .themes: "Alternative app icons."
        case .sync: "Keep your devices in step."
        case .trashRestore: "Get back what you deleted."
        }
    }

    var icon: String {
        switch self {
        case .duressPassword: "flame"
        case .biometricUnlock: "faceid"
        case .albums: "rectangle.stack"
        case .backupExport: "externaldrive.fill"
        case .bulkExport: "square.and.arrow.up.on.square"
        case .multipleVaults: "lock.rectangle.stack"
        case .intruderAlert: "bell.badge"
        case .themes: "paintpalette"
        case .sync: "arrow.triangle.2.circlepath"
        case .trashRestore: "arrow.uturn.backward.circle"
        }
    }
}

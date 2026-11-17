import SwiftUI

/// Version, license and contact. Links open outside the app; the app itself makes no network connections.
struct AboutView: View {
    static let supportMail = "support@zeroenclave.com"

    /// Website pages in German or English, matching the app language.
    enum Site {
        static let base = URL(string: "https://zeroenclave.com")!

        static var language: String {
            Bundle.main.preferredLocalizations.first == "de" ? "de" : "en"
        }

        static var home: URL { base.appending(path: "\(language)/") }
        static var openSource: URL { base.appending(path: "\(language)/open-source") }
        static var privacy: URL {
            base.appending(path: language == "de" ? "de/datenschutz" : "en/privacy")
        }
    }

    static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }

    var body: some View {
        Form {
            Section {
                VStack(spacing: 8) {
                    AppMark(size: 72)
                    Text(verbatim: "Zero Enclave")
                        .font(.title2.weight(.bold))
                    Text(verbatim: "Private by design.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .listRowBackground(Color.clear)
            }

            Section {
                LabeledContent("Version", value: Self.version)
                LabeledContent("License") {
                    Text(verbatim: "Open Source (GPLv3)")
                }
            }

            Section {
                link("Support", systemName: "envelope.fill", detail: Self.supportMail,
                     to: URL(string: "mailto:\(Self.supportMail)")!)
                link("Website", systemName: "globe", detail: "zeroenclave.com", to: Site.home)
                link("Source code", systemName: "chevron.left.forwardslash.chevron.right", to: Site.openSource)
                link("Privacy policy", systemName: "hand.raised.fill", to: Site.privacy)
            } footer: {
                Text("Zero Enclave makes no network connections. Data leaves your device only through an export.")
            }
        }
        .navigationTitle("About")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func link(
        _ title: LocalizedStringKey, systemName: String, detail: String? = nil, to url: URL
    ) -> some View {
        Link(destination: url) {
            HStack {
                SettingsLabel(title: title, systemName: systemName)
                Spacer()
                if let detail {
                    Text(verbatim: detail)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
                Image(systemName: "arrow.up.forward")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
        }
        .foregroundStyle(Theme.ink)
    }
}

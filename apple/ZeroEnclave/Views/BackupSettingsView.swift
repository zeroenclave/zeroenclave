import SwiftUI

/// Encrypted export, import and full restore of the vault.
struct BackupSettingsView: View {
    let vault: VaultService

    @Environment(Entitlements.self) private var entitlements
    @State private var gate = PremiumGate()

    @State private var exportProgress: Double?
    @State private var exportDocument: BackupDocument?
    @State private var showExporter = false
    @State private var showImporter = false
    @State private var importURL: URL?
    @State private var importMode = BackupImportView.Mode.merge
    @State private var backupError: String?

    var body: some View {
        Form {
            Section {
                // Export is premium; importing and restoring stay free.
                Button { gate.perform(.backupExport, entitlements: entitlements) { startExport() } } label: {
                    HStack {
                        SettingsLabel(title: "Export encrypted backup", systemName: "square.and.arrow.up.fill")
                        PremiumBadge()
                        if let exportProgress {
                            Spacer()
                            ProgressView(value: exportProgress)
                                .frame(width: 80)
                                .accessibilityLabel("Export progress")
                                .accessibilityValue(
                                    Text(exportProgress, format: .percent.precision(.fractionLength(0))))
                        }
                    }
                }
                .foregroundStyle(Theme.ink)
            } footer: {
                Text("Encrypted. Also part of your device backup in iCloud or on your computer.")
            }

            Section {
                Button {
                    importMode = .merge
                    showImporter = true
                } label: {
                    SettingsLabel(title: "Import backup", systemName: "square.and.arrow.down.fill")
                }
                .foregroundStyle(Theme.ink)
            } footer: {
                Text("Brings back photos from an earlier backup of this vault. Photos already here stay.")
            }
        }
        .disabled(exportProgress != nil)
        .navigationTitle("Backup")
        .navigationBarTitleDisplayMode(.inline)
        // Leaving the page during an export would present the save dialog off screen.
        .navigationBarBackButtonHidden(exportProgress != nil)
        .toolbar(exportProgress != nil ? .hidden : .visible, for: .tabBar)
        .sheet(isPresented: $gate.isPresentingRequired) {
            PremiumRequiredSheet(feature: gate.requested)
                .privacyCover()
        }
        .fileExporter(
            isPresented: $showExporter, document: exportDocument,
            contentType: .zeroEnclaveBackup, defaultFilename: BackupName.defaultName()
        ) { result in
            if case .failure = result { backupError = String(localized: "The backup could not be saved.") }
        }
        .onChange(of: showExporter) { _, shown in
            if !shown { discardExport() }
        }
        .fileImporter(
            isPresented: $showImporter, allowedContentTypes: [.zeroEnclaveBackup, .data]
        ) { result in
            if case .success(let url) = result { importURL = url }
        }
        .sheet(
            isPresented: Binding(get: { importURL != nil }, set: { if !$0 { importURL = nil } })
        ) {
            if let importURL {
                BackupImportView(vault: vault, url: importURL, mode: importMode) { self.importURL = nil }
                    .privacyCover()
            }
        }
        .alert(
            "Backup", isPresented: Binding(get: { backupError != nil }, set: { if !$0 { backupError = nil } })
        ) {
            Button("OK") {}
        } message: {
            Text(backupError ?? "")
        }
        .onDisappear(perform: discardExport)
    }

    private func startExport() {
        guard exportProgress == nil else { return }
        exportProgress = 0
        Task {
            defer { exportProgress = nil }
            let url: URL
            do {
                url = try TemporaryFiles.makeDirectory()
                    .appending(path: BackupName.defaultName() + ".zenx", directoryHint: .notDirectory)
            } catch {
                backupError = VaultService.backupMessage(for: error)
                return
            }
            let failure = await vault.exportBackup(to: url) { done, total in
                exportProgress = total > 0 ? Double(done) / Double(total) : 0
            }
            if let failure {
                TemporaryFiles.remove(url)
                backupError = failure
                return
            }
            exportDocument = BackupDocument(url: url)
            showExporter = true
        }
    }

    private func discardExport() {
        guard !showExporter else { return }
        TemporaryFiles.remove(exportDocument?.url)
        exportDocument = nil
    }
}

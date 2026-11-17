import SwiftUI

/// Shown after an import; offers to delete the originals from the photo library.
struct ImportResultSheet: View {
    let summary: ImportCoordinator.Summary
    let onDone: () -> Void

    @State private var deleteOriginals = false
    @State private var isWorking = false
    @State private var failedToDelete = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Imported \(summary.imported) items.")
                    if summary.failed > 0 {
                        Notice("\(summary.failed) items could not be imported.", tone: .warning)
                    }
                }
                if !summary.assetIdentifiers.isEmpty {
                    Section {
                        Toggle("Delete originals after import", isOn: $deleteOriginals)
                    } footer: {
                        Text(
                            "Deleted photos stay in \"Recently Deleted\" in the Photos app for 30 days. Zero Enclave asks for photo library access only to do this."
                        )
                    }
                }
                if failedToDelete {
                    Notice("The originals could not be deleted. Check the photo library access in Settings.")
                }
            }
            .navigationTitle("Import finished")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: finish).disabled(isWorking)
                }
            }
        }
        .interactiveDismissDisabled(isWorking)
        .presentationDetents([.medium])
    }

    private func finish() {
        guard deleteOriginals else {
            onDone()
            return
        }
        isWorking = true
        Task {
            let ok = await PhotoLibraryDeleter.delete(assetIdentifiers: summary.assetIdentifiers)
            isWorking = false
            if ok { onDone() } else { failedToDelete = true; deleteOriginals = false }
        }
    }
}

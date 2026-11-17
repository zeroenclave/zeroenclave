import SwiftUI

/// Lists the albums and adds the given items to the chosen one, or to a new album.
struct AddToAlbumSheet: View {
    let store: LibraryStore
    let itemIDs: Set<String>
    let onDone: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var showCreate = false
    @State private var failed = false

    var body: some View {
        NavigationStack {
            List {
                Button("New album…", systemImage: "plus") { showCreate = true }
                ForEach(store.albums) { album in
                    Button {
                        Task { await add(to: album.id) }
                    } label: {
                        HStack {
                            Text(album.name)
                            Spacer()
                            if album.locked {
                                Image(systemName: "lock.fill")
                                    .foregroundStyle(.secondary)
                                    .accessibilityHidden(true)
                            } else {
                                Text("\(album.itemCount)")
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .foregroundStyle(.primary)
                    .accessibilityLabel(Text("Add to album \(album.name)"))
                }
            }
            .navigationTitle("Add to album")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .sheet(isPresented: $showCreate) {
                AlbumCreateSheet(store: store) { id in
                    Task { await add(to: id) }
                }
            }
            .alert("The items could not be added.", isPresented: $failed) {
                Button("OK") {}
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func add(to albumID: String) async {
        if await store.add(ids: itemIDs, to: albumID) {
            onDone()
            dismiss()
        } else {
            failed = true
        }
    }
}

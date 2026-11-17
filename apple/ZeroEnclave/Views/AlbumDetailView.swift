import SwiftUI

/// The photos of one album, with the same grid as the gallery.
struct AlbumDetailView: View {
    let store: LibraryStore
    let albumID: String
    let isImporting: Bool
    let onImport: () -> Void
    let onCapture: () -> Void
    let onOpen: (LibraryItem) -> Void

    @State private var isSelecting = false
    @State private var selection = Set<String>()
    @State private var showSettings = false
    @State private var confirmDelete = false
    @Environment(\.dismiss) private var dismiss
    @Environment(Entitlements.self) private var entitlements

    /// Without premium an album can be viewed and deleted, not changed.
    private var canEdit: Bool { entitlements.hasPremium }

    private var album: LibraryAlbum? { store.albums.first { $0.id == albumID } }
    private var items: [LibraryItem] { store.items(in: albumID) }
    /// Open albums and unlocked locked albums show their content.
    private var isAccessible: Bool {
        guard let album else { return false }
        return !album.locked || store.albumLock.isOpen(albumID)
    }

    var body: some View {
        Group {
            if let album, !isAccessible {
                AlbumLockedView(store: store, album: album)
            } else if items.isEmpty {
                ContentUnavailableView {
                    Label("No photos in this album", systemImage: "photo.on.rectangle.angled")
                } description: {
                    Text("Import photos here or add them from All Photos.")
                } actions: {
                    if canEdit {
                        Menu("Import") { importActions }
                            .buttonStyle(.glassProminent)
                            .foregroundStyle(Theme.onAccent)
                            .disabled(isImporting)
                    }
                }
            } else {
                PhotoGrid(
                    store: store, items: items, isSelecting: isSelecting, selection: $selection,
                    onOpen: onOpen)
            }
        }
        .navigationTitle(album?.name ?? "")
        .navigationBarTitleDisplayMode(.inline)
        .onDisappear { store.albumLock.close(albumID) }
        .onChange(of: album == nil) { _, deleted in if deleted { dismiss() } }
        .confirmSheet(
            isPresented: $confirmDelete, systemImage: "trash", title: "\(selection.count) items selected",
            message: "Removing keeps the items in All Photos. Deleted items stay in the Trash for 30 days.",
            actions: (canEdit ? [ConfirmAction(title: "Remove from album", action: removeSelected)] : [])
                + [ConfirmAction(title: "Delete", role: .destructive, action: deleteSelected)]
        )
        .sheet(isPresented: $showSettings) {
            AlbumSettingsView(store: store, albumID: albumID)
        }
        .toolbar {
            // A locked album offers no actions until its code is entered.
            if isAccessible, isSelecting {
                ToolbarItem(placement: .primaryAction) {
                    Button("Delete", systemImage: "trash", role: .destructive) { confirmDelete = true }
                        .disabled(selection.isEmpty)
                        .accessibilityLabel("Delete selected items")
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Done", action: endSelecting)
                }
            } else if isAccessible {
                ToolbarItem(placement: .primaryAction) {
                    Button("Settings", systemImage: "gearshape") { showSettings = true }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Select") { isSelecting = true }
                        .disabled(items.isEmpty)
                }
                if canEdit {
                    ToolbarItem(placement: .primaryAction) {
                        Menu("Import", systemImage: "plus") { importActions }
                            .disabled(isImporting)
                            .accessibilityLabel("Import photos and videos into this album")
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var importActions: some View {
        Button("Import from Photos", systemImage: "photo.on.rectangle", action: onImport)
        if CameraPicker.isAvailable {
            Button("Take Photo or Video", systemImage: "camera", action: onCapture)
        }
    }

    private func removeSelected() {
        let ids = selection
        Task {
            _ = await store.remove(ids: ids, from: albumID)
            endSelecting()
        }
    }

    private func deleteSelected() {
        let ids = selection
        Task {
            _ = await store.trash(ids: ids)
            endSelecting()
        }
    }

    private func endSelecting() {
        isSelecting = false
        selection = []
    }
}

import SwiftUI

/// Navigation value that opens an album.
struct AlbumRoute: Hashable {
    let id: String
}

/// Grid of albums with create, rename and delete. Without premium the albums stay viewable;
/// creating and changing them needs premium, deleting does not.
struct AlbumsView: View {
    let store: LibraryStore

    @Environment(Entitlements.self) private var entitlements
    @State private var gate = PremiumGate()

    @State private var showCreate = false
    @State private var settingsAlbum: LibraryAlbum?
    @State private var renaming: LibraryAlbum?
    @State private var renameText = ""
    @State private var deleting: LibraryAlbum?
    @State private var failed = false

    var body: some View {
        Group {
            if store.albums.isEmpty {
                ContentUnavailableView {
                    Label("No albums yet", systemImage: "rectangle.stack")
                } description: {
                    Text("Group your photos into albums. Photos stay in All Photos.")
                } actions: {
                    Button("New album") { startCreate() }
                        .buttonStyle(.glassProminent)
                        .foregroundStyle(Theme.onAccent)
                }
            } else {
                ScrollView {
                    LazyVGrid(
                        columns: [GridItem(.adaptive(minimum: 150), spacing: 16)], spacing: 16
                    ) {
                        ForEach(store.albums) { album in
                            NavigationLink(value: AlbumRoute(id: album.id)) {
                                AlbumCell(store: store, album: album)
                            }
                            .buttonStyle(.plain)
                            .contextMenu {
                                // Locked albums are managed from inside, after the code.
                                if !album.locked {
                                    openAlbumActions(album)
                                }
                            }
                        }
                    }
                    .padding()
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("New album", systemImage: "plus") { startCreate() }
                    .accessibilityLabel("Create album")
            }
        }
        .sheet(isPresented: $gate.isPresentingRequired) {
            PremiumRequiredSheet(feature: gate.requested)
        }
        .sheet(isPresented: $showCreate) {
            AlbumCreateSheet(store: store)
        }
        .sheet(item: $settingsAlbum) { album in
            AlbumSettingsView(store: store, albumID: album.id)
        }
        .albumNameAlert(
            "Rename album", confirm: "Rename",
            isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } }),
            text: $renameText
        ) { name in
            guard let album = renaming else { return }
            Task { if await !store.renameAlbum(id: album.id, to: name) { failed = true } }
        }
        .confirmSheet(
            item: $deleting, systemImage: "trash", title: "Delete this album?",
            message: "Photos stay in All Photos."
        ) { album in
            [
                ConfirmAction(title: "Delete album", role: .destructive) {
                    Task { if await !store.deleteAlbum(id: album.id) { failed = true } }
                }
            ]
        }
        .alert("The album could not be changed.", isPresented: $failed) {
            Button("OK") {}
        }
    }

    @ViewBuilder
    private func openAlbumActions(_ album: LibraryAlbum) -> some View {
        if entitlements.hasPremium {
            Button("Rename", systemImage: "pencil") {
                renameText = album.name
                renaming = album
            }
            Button("Settings", systemImage: "gearshape") {
                settingsAlbum = album
            }
        }
        Button("Delete", systemImage: "trash", role: .destructive) {
            deleting = album
        }
    }

    private func startCreate() {
        gate.perform(.albums, entitlements: entitlements) { showCreate = true }
    }
}

private struct AlbumCell: View {
    let store: LibraryStore
    let album: LibraryAlbum

    @State private var image: UIImage?

    private var cover: LibraryItem? {
        album.coverID.flatMap { id in store.items.first { $0.id == id } }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Color.secondary.opacity(0.15)
                .aspectRatio(1, contentMode: .fit)
                .overlay {
                    if let image, !album.locked {
                        Image(uiImage: image)
                            .resizable()
                            .scaledToFill()
                    } else {
                        Image(systemName: album.locked ? "lock.fill" : "photo.on.rectangle")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                    }
                }
                .clipShape(.rect(cornerRadius: 12))
            Text(album.name)
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
            // A locked album shows neither cover nor count.
            if album.locked {
                Text("Locked")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("\(album.itemCount) items")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .contentShape(.rect)
        .task(id: album.locked ? nil : album.coverID) {
            guard !album.locked, let cover else {
                image = nil
                return
            }
            image = await store.thumbnail(for: cover, large: false)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(
            album.locked
                ? Text("Locked album \(album.name)")
                : Text("Album \(album.name), \(album.itemCount) items"))
        .accessibilityAddTraits(.isButton)
    }
}

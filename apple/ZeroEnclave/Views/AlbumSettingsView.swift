import SwiftUI

/// Sets a new code for an album and keeps it open afterwards.
struct AlbumNewCodeSheet: View {
    let store: LibraryStore
    let albumID: String

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            AlbumCodeFlow(context: store.albums.first { $0.id == albumID }?.name) { code in
                guard await store.setAlbumCode(id: albumID, code) else { return false }
                dismiss()
                return true
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", systemImage: "xmark") { dismiss() }
                }
            }
        }
        .presentationDetents([.large])
    }
}

/// Visibility in All Photos and the code of one album.
struct AlbumSettingsView: View {
    @Environment(Entitlements.self) private var entitlements

    private enum Protected { case change, remove }

    let store: LibraryStore
    let albumID: String

    @Environment(\.dismiss) private var dismiss
    @State private var pending: Protected?
    @State private var showPassword = false
    @State private var showNewCode = false
    @State private var confirmRemove = false
    @State private var confirmDelete = false
    @State private var renaming = false
    @State private var renameText = ""
    @State private var failed = false

    private var album: LibraryAlbum? { store.albums.first { $0.id == albumID } }

    var body: some View {
        NavigationStack {
            Form {
                if let album {
                    if !entitlements.hasPremium {
                        Section {
                            Label {
                                Text("Without Premium you can view and delete this album, not change it.")
                            } icon: {
                                Image(systemName: "sparkles").foregroundStyle(Theme.mint)
                            }
                            .font(.footnote)
                        }
                    }
                    Section {
                        Toggle(
                            "Show in All Photos",
                            isOn: Binding(
                                get: { album.showInAll },
                                set: { value in
                                    Task { if await !store.setShowInAll(id: albumID, value) { failed = true } }
                                }))
                            .disabled(!entitlements.hasPremium)
                    } footer: {
                        Text("When off, photos in this album are hidden from All Photos. They stay visible in the album.")
                    }
                    Section {
                        Group {
                            if album.locked {
                                Button("Change code…") { require(.change) }
                                Button("Remove code", role: .destructive) { require(.remove) }
                            } else {
                                Button("Lock with code…") { showNewCode = true }
                            }
                        }
                        .disabled(!entitlements.hasPremium)
                    } header: {
                        Text(album.locked ? "Locked album" : "Open album")
                    } footer: {
                        AlbumLockFooter()
                    }
                    Section {
                        Button("Rename…") {
                            renameText = album.name
                            renaming = true
                        }
                        .disabled(!entitlements.hasPremium)
                        Button("Delete album", role: .destructive) { confirmDelete = true }
                    }
                }
            }
            .navigationTitle("Album settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .masterPasswordPrompt(
                store: store, isPresented: $showPassword,
                message: "Enter your master password to change the lock of this album."
            ) {
                perform(pending)
            }
            .confirmSheet(
                isPresented: $confirmRemove, systemImage: "lock.open", title: "Remove the code?",
                message: "The album becomes an open album.",
                actions: [
                    ConfirmAction(title: "Remove code", role: .destructive) {
                        Task { if await !store.setAlbumCode(id: albumID, nil) { failed = true } }
                    }
                ])
            .sheet(isPresented: $showNewCode) {
                AlbumNewCodeSheet(store: store, albumID: albumID)
            }
            .albumNameAlert(
                "Rename album", confirm: "Rename", isPresented: $renaming, text: $renameText
            ) { name in
                Task { if await !store.renameAlbum(id: albumID, to: name) { failed = true } }
            }
            .confirmSheet(
                isPresented: $confirmDelete, systemImage: "trash", title: "Delete this album?",
                message: "Photos stay in your vault and appear in All Photos again.",
                actions: [
                    ConfirmAction(title: "Delete album", role: .destructive) {
                        Task {
                            if await store.deleteAlbum(id: albumID) { dismiss() } else { failed = true }
                        }
                    }
                ])
            .alert("The album could not be changed.", isPresented: $failed) {
                Button("OK") {}
            }
        }
    }

    /// An open album may be changed directly; otherwise the master password is required.
    private func require(_ action: Protected) {
        pending = action
        if store.albumLock.isOpen(albumID) {
            perform(action)
        } else {
            showPassword = true
        }
    }

    private func perform(_ action: Protected?) {
        switch action {
        case .change: showNewCode = true
        case .remove: confirmRemove = true
        case nil: break
        }
        pending = nil
    }
}

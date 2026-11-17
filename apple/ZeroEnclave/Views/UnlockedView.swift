import SwiftUI

/// The gallery of the unlocked vault.
struct UnlockedView: View {
    let vault: VaultService

    private enum Section: Hashable { case photos, albums, trash, settings }

    /// What the viewer shows: the whole library, one album, or the trash.
    private struct ViewerTarget: Identifiable {
        let startID: String
        let albumID: String?
        var inTrash = false
        var id: String { startID }
    }

    @Environment(Entitlements.self) private var entitlements
    @State private var store: LibraryStore
    @State private var importer: ImportCoordinator
    @State private var gate = PremiumGate()
    @State private var section = Section.photos
    @State private var showPicker = false
    @State private var showCamera = false
    /// Album that receives the items of the running or next import.
    @State private var importAlbumID: String?
    @State private var pickedSources: [any ImportSource] = []
    @State private var isSelecting = false
    @State private var selection = Set<String>()
    @State private var confirmDelete = false
    @State private var showAddToAlbum = false
    @State private var viewing: ViewerTarget?
    @State private var settingsPath = NavigationPath()
    @State private var sharedFile: SharedFile?
    /// Kept apart from `sharedFile`, which is already nil when the sheet's dismiss handler runs.
    @State private var tempURL: URL?
    @State private var exportMessage: String?
    /// The read-only notice is shown once per unlock unless the user confirms the files.
    @State private var readOnlyNoticeDismissed = false

    init(vault: VaultService) {
        self.vault = vault
        let store = LibraryStore(vault: vault)
        _store = State(initialValue: store)
        _importer = State(initialValue: ImportCoordinator(vault: vault, store: store))
        #if DEBUG
            let demo: [String: Section] = ["albums": .albums, "trash": .trash, "settings": .settings, "encryption": .settings]
            if DemoMode.isRequested, let screen = DemoMode.screen, let start = demo[screen] {
                _section = State(initialValue: start)
                if screen == "encryption" {
                    _settingsPath = State(initialValue: NavigationPath([SettingsView.Route.encryption]))
                }
            }
        #endif
    }

    var body: some View {
        TabView(selection: sectionSelection) {
            Tab("All Photos", systemImage: "photo.on.rectangle", value: Section.photos) {
                NavigationStack {
                    photos
                        .navigationTitle("All Photos")
                        .toolbar { commonToolbar }
                        .toolbar { photosToolbar }
                        .toolbar(isSelecting ? .hidden : .visible, for: .tabBar)
                        .confirmSheet(
                            isPresented: $confirmDelete, systemImage: "trash",
                            title: "Delete \(selection.count) items?",
                            message: "Deleted items stay in the Trash for 30 days.",
                            actions: [
                                ConfirmAction(title: "Delete", role: .destructive, action: trashSelection)
                            ]
                        )
                        .safeAreaInset(edge: .bottom) { progressBar }
                }
            }
            Tab("Albums", systemImage: "rectangle.stack", value: Section.albums) {
                NavigationStack {
                    AlbumsView(store: store)
                        .navigationTitle("Albums")
                        .toolbar { commonToolbar }
                        .navigationDestination(for: AlbumRoute.self) { route in
                            AlbumDetailView(
                                store: store, albumID: route.id, isImporting: importer.isRunning,
                                onImport: { startImport(into: route.id) },
                                onCapture: { startCapture(into: route.id) },
                                onOpen: { viewing = ViewerTarget(startID: $0.id, albumID: route.id) })
                        }
                        .safeAreaInset(edge: .bottom) { progressBar }
                }
            }
            Tab("Trash", systemImage: "trash", value: Section.trash) {
                NavigationStack {
                    TrashView(
                        store: store, gate: gate, isSelecting: $isSelecting, selection: $selection,
                        onOpen: { viewing = ViewerTarget(startID: $0.id, albumID: nil, inTrash: true) }
                    )
                    .navigationTitle("Trash")
                    .toolbar { commonToolbar }
                    .toolbar(isSelecting ? .hidden : .visible, for: .tabBar)
                }
            }
            .badge(store.trashed.count)
            Tab("Settings", systemImage: "gearshape", value: Section.settings) {
                NavigationStack(path: $settingsPath) {
                    SettingsView(vault: vault)
                        .navigationTitle("Settings")
                        .toolbar { commonToolbar }
                }
            }
        }
        .task {
            await store.reload()
            await store.purgeExpired()
            #if DEBUG
                if DemoMode.isRequested, DemoMode.screen == "viewer", let first = store.photos.dropFirst(3).first {
                    viewing = ViewerTarget(startID: first.id, albumID: nil)
                }
            #endif
        }
        // The import starts only after the picker is fully dismissed: a quick import would
        // otherwise present its result sheet during the dismissal and break the presentation state.
        .fullScreenCover(
            isPresented: $showPicker,
            onDismiss: { startPickedImport() }
        ) {
            PhotoPicker { sources in
                pickedSources = sources
                showPicker = false
            }
            .ignoresSafeArea()
            .privacyCover()
        }
        .fullScreenCover(
            isPresented: $showCamera, onDismiss: { startPickedImport(fromCamera: true) }
        ) {
            CameraPicker { source in
                pickedSources = source.map { [$0] } ?? []
                showCamera = false
            }
            .ignoresSafeArea()
            .privacyCover()
        }
        .sheet(isPresented: $showAddToAlbum) {
            AddToAlbumSheet(store: store, itemIDs: selection) {
                selection = []
                isSelecting = false
            }
        }
        .sheet(isPresented: $gate.isPresentingRequired) {
            PremiumRequiredSheet(feature: gate.requested)
        }
        .sheet(
            isPresented: Binding(
                get: { vault.isReadOnly && !readOnlyNoticeDismissed },
                set: { if !$0 { readOnlyNoticeDismissed = true } })
        ) {
            ReadOnlyNoticeSheet(vault: vault)
                .privacyCover()
        }
        .fullScreenCover(item: $viewing) { target in
            ViewerView(
                store: store, startID: target.startID, albumID: target.albumID, inTrash: target.inTrash
            )
            .privacyCover()
        }
        .sheet(
            isPresented: Binding(
                get: { importer.summary != nil }, set: { if !$0 { importer.summary = nil } })
        ) {
            if let summary = importer.summary {
                ImportResultSheet(summary: summary) { importer.summary = nil }
                    .privacyCover()
            }
        }
        .sheet(item: $sharedFile, onDismiss: removeSharedFile) { file in
            ShareSheet(url: file.url, onDone: removeSharedFile)
        }
        .alert(
            "Export", isPresented: Binding(get: { exportMessage != nil }, set: { if !$0 { exportMessage = nil } })
        ) {
            Button("OK") {}
        } message: {
            Text(exportMessage ?? "")
        }
        .onDisappear { importer.cancel() }
    }

    @ViewBuilder
    private var photos: some View {
        if store.photos.isEmpty {
            ContentUnavailableView {
                Label("No photos yet", systemImage: "photo.on.rectangle.angled")
            } description: {
                Text("Photos and videos you add to the vault will appear here.")
            } actions: {
                Menu("Import") { importActions(into: nil) }
                    .buttonStyle(.glassProminent)
                    .foregroundStyle(Theme.onAccent)
            }
        } else {
            PhotoGrid(
                store: store, items: store.photos, isSelecting: isSelecting, selection: $selection,
                onOpen: { viewing = ViewerTarget(startID: $0.id, albumID: nil) },
                actions: GridActions(
                    share: share,
                    addToAlbum: { item in
                        gate.perform(.albums, entitlements: entitlements) {
                            selection = [item.id]
                            showAddToAlbum = true
                        }
                    },
                    delete: { item in
                        selection = [item.id]
                        confirmDelete = true
                    }))
        }
    }

    /// Albums are a premium feature; selecting the tab goes through the gate.
    private var sectionSelection: Binding<Section> {
        Binding(
            get: { section },
            set: { newValue in
                if newValue == .albums {
                    // Existing albums stay viewable without premium; creating the first one needs it.
                    if store.albums.isEmpty {
                        gate.perform(.albums, entitlements: entitlements) { show(.albums) }
                    } else {
                        show(.albums)
                    }
                } else if newValue == .trash {
                    gate.perform(.trashRestore, entitlements: entitlements) { show(.trash) }
                } else if newValue == .settings {
                    // Backup restore and import must not run alongside a photo import.
                    if !importer.isRunning { show(.settings) }
                } else {
                    show(newValue)
                }
            })
    }

    /// Decrypts the original into a temporary file for the share sheet; removed when it closes.
    private func share(_ item: LibraryItem) {
        Task {
            guard let data = await store.originalData(for: item) else {
                exportMessage = String(localized: "The item could not be read.")
                return
            }
            do {
                let url = try ItemExport.writeTemporary(data, name: ItemExport.fileName(for: item))
                tempURL = url
                sharedFile = SharedFile(url: url)
            } catch {
                exportMessage = String(localized: "The item could not be exported.")
            }
        }
    }

    private func removeSharedFile() {
        TemporaryFiles.remove(tempURL)
        tempURL = nil
        sharedFile = nil
    }

    private func trashSelection() {
        let ids = selection
        Task {
            _ = await store.trash(ids: ids)
            selection = []
            isSelecting = false
        }
    }

    private func show(_ new: Section) {
        // A backup import in Settings may have changed the library.
        if section == .settings, new != .settings { Task { await store.reload() } }
        section = new
        isSelecting = false
        selection = []
    }

    private func startImport(into albumID: String?) {
        importAlbumID = albumID
        showPicker = true
    }

    private func startCapture(into albumID: String?) {
        importAlbumID = albumID
        showCamera = true
    }

    private func startPickedImport(fromCamera: Bool = false) {
        let sources = pickedSources
        pickedSources = []
        importer.start(sources, albumID: importAlbumID, reportSuccess: !fromCamera)
        importAlbumID = nil
    }

    @ViewBuilder
    private func importActions(into albumID: String?) -> some View {
        Button("Import from Photos", systemImage: "photo.on.rectangle") { startImport(into: albumID) }
        if CameraPicker.isAvailable {
            Button("Take Photo or Video", systemImage: "camera") { startCapture(into: albumID) }
        }
    }

    @ViewBuilder
    private var progressBar: some View {
        if importer.isRunning {
            HStack(spacing: 12) {
                ProgressView(value: Double(importer.done), total: Double(max(importer.total, 1)))
                Text("Importing \(min(importer.done + 1, importer.total)) of \(importer.total)")
                    .font(.footnote)
                Button("Cancel", role: .cancel) { importer.cancel() }
                    .font(.footnote)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .glassEffect(.regular, in: .capsule)
            .padding(.horizontal)
            .padding(.bottom, 8)
            .accessibilityElement(children: .combine)
        }
    }

    @ToolbarContentBuilder
    private var commonToolbar: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            Button("Lock", systemImage: "lock.fill") { vault.lockManually() }
                .accessibilityLabel("Lock vault")
        }
    }

    @ToolbarContentBuilder
    private var photosToolbar: some ToolbarContent {
        if isSelecting {
            ToolbarItem(placement: .primaryAction) {
                Button("Add to album", systemImage: "rectangle.stack.badge.plus") {
                    gate.perform(.albums, entitlements: entitlements) { showAddToAlbum = true }
                }
                .disabled(selection.isEmpty)
                .accessibilityLabel("Add selected items to album")
            }
            ToolbarItem(placement: .primaryAction) {
                Button("Delete", systemImage: "trash", role: .destructive) { confirmDelete = true }
                    .disabled(selection.isEmpty)
                    .accessibilityLabel("Delete selected items")
            }
            ToolbarItem(placement: .primaryAction) {
                Button("Done") {
                    isSelecting = false
                    selection = []
                }
            }
        } else {
            ToolbarItem(placement: .primaryAction) {
                Button("Select") { isSelecting = true }
                    .disabled(store.photos.isEmpty)
            }
            ToolbarItem(placement: .primaryAction) {
                Menu("Import", systemImage: "plus") { importActions(into: nil) }
                    .disabled(importer.isRunning)
                    .accessibilityLabel("Import photos and videos")
            }
        }
    }
}

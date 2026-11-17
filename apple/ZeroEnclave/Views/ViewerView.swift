import AVKit
import SwiftUI

/// Full-screen pager over the library.
struct ViewerView: View {
    let store: LibraryStore
    /// Restricts the pager to one album; nil shows the whole library.
    let albumID: String?
    /// Shows Recently Deleted: view only, deleting is permanent.
    let inTrash: Bool
    @State var currentID: String
    @Environment(\.dismiss) private var dismiss
    @Environment(Entitlements.self) private var entitlements
    @State private var gate = PremiumGate()
    @State private var showAddToAlbum = false
    @State private var showInfo = false
    @State private var confirmDelete = false
    @State private var isExporting = false
    @State private var sharedFile: SharedFile?
    /// Kept apart from `sharedFile`, which is already nil when the sheet's dismiss handler runs.
    @State private var tempURL: URL?
    @State private var exportMessage: String?

    init(
        store: LibraryStore, startID: String, albumID: String? = nil, inTrash: Bool = false
    ) {
        self.store = store
        self.albumID = albumID
        self.inTrash = inTrash
        _currentID = State(initialValue: startID)
    }

    private var items: [LibraryItem] {
        // Items hidden from All Photos (locked albums) are not viewable from the trash.
        if inTrash { return store.trashed.filter { !$0.hiddenInAll } }
        return albumID.map(store.items(in:)) ?? store.photos
    }

    private var current: LibraryItem? { items.first { $0.id == currentID } }

    private var dateTitle: String {
        current?.date.formatted(.dateTime.day().month(.wide).year()) ?? ""
    }

    var body: some View {
        NavigationStack {
            TabView(selection: $currentID) {
                ForEach(items) { item in
                    ViewerPage(store: store, item: item).tag(item.id)
                }
            }
            .tabViewStyle(.page(indexDisplayMode: .never))
            .background(.black)
            .toolbarBackground(.visible, for: .navigationBar)
            .navigationTitle(Text(dateTitle))
            .navigationBarTitleDisplayMode(.inline)
            // Photo first: white controls on black, actions at the bottom within thumb reach.
            .toolbarColorScheme(.dark, for: .navigationBar, .bottomBar)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Close", systemImage: "xmark") { dismiss() }
                        .accessibilityLabel("Close viewer")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Info", systemImage: "info.circle") { showInfo = true }
                        .disabled(current == nil)
                }
                ToolbarItem(placement: .bottomBar) {
                    Menu("Share", systemImage: "square.and.arrow.up") {
                        Button("Save to Photos", systemImage: "photo.badge.plus") { export(.photos) }
                        Button("Share…", systemImage: "square.and.arrow.up") { export(.share) }
                    }
                    .disabled(current == nil || isExporting)
                    .accessibilityLabel("Export original")
                }
                ToolbarSpacer(.flexible, placement: .bottomBar)
                if !inTrash {
                    ToolbarItem(placement: .bottomBar) {
                        Button("Add to album", systemImage: "rectangle.stack.badge.plus") {
                            gate.perform(.albums, entitlements: entitlements) { showAddToAlbum = true }
                        }
                        .disabled(current == nil)
                        .accessibilityLabel("Add to album")
                    }
                    ToolbarSpacer(.flexible, placement: .bottomBar)
                }
                ToolbarItem(placement: .bottomBar) {
                    Button("Delete", systemImage: "trash", role: .destructive) { confirmDelete = true }
                        .disabled(current == nil)
                        .accessibilityLabel(inTrash ? "Delete permanently" : "Delete")
                }
            }
            .confirmSheet(
                isPresented: $confirmDelete, systemImage: "trash",
                title: inTrash ? "Delete this item permanently?" : "Delete this item?",
                message: inTrash ? "This cannot be undone." : "Deleted items stay in the Trash for 30 days.",
                actions: [
                    ConfirmAction(
                        title: inTrash ? "Delete permanently" : "Delete", role: .destructive,
                        action: deleteCurrent)
                ])
            .sheet(isPresented: $showAddToAlbum) {
                if let current {
                    AddToAlbumSheet(store: store, itemIDs: [current.id]) {}
                }
            }
            .sheet(isPresented: $gate.isPresentingRequired) {
                PremiumRequiredSheet(feature: gate.requested)
            }
            .sheet(isPresented: $showInfo) {
                if let current { InfoSheet(item: current).privacyCover() }
            }
            .sheet(item: $sharedFile, onDismiss: removeSharedFile) { file in
                ShareSheet(url: file.url, onDone: removeSharedFile)
                    .privacyCover()
            }
            .alert(
                "Export", isPresented: Binding(get: { exportMessage != nil }, set: { if !$0 { exportMessage = nil } })
            ) {
                Button("OK") {}
            } message: {
                Text(exportMessage ?? "")
            }
            .onDisappear(perform: removeSharedFile)
        }
        .preferredColorScheme(.dark)
        .tint(.white)
    }

    private enum Destination { case photos, share }

    /// Decrypts the original of the current item into memory and hands it to its destination.
    private func export(_ destination: Destination) {
        guard let item = current, !isExporting else { return }
        isExporting = true
        Task {
            defer { isExporting = false }
            guard let data = await store.originalData(for: item) else {
                exportMessage = String(localized: "The item could not be read.")
                return
            }
            do {
                switch destination {
                case .photos:
                    try await ItemExport.saveToPhotos(data, item: item)
                    exportMessage = String(localized: "Saved to Photos.")
                case .share:
                    let url = try ItemExport.writeTemporary(data, name: ItemExport.fileName(for: item))
                    tempURL = url
                    sharedFile = SharedFile(url: url)
                }
            } catch ItemExport.Failure.denied {
                exportMessage = String(localized: "Allow adding photos in the iOS Settings to save items.")
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

    private func deleteCurrent() {
        let items = items
        guard let index = items.firstIndex(where: { $0.id == currentID }) else { return }
        let neighbour = items.indices.contains(index + 1) ? index + 1 : index - 1
        let next = items.indices.contains(neighbour) ? items[neighbour].id : nil
        Task {
            let id = currentID
            let done = inTrash ? await store.deletePermanently(ids: [id]) : await store.trash(ids: [id])
            guard done else { return }
            if let next { currentID = next } else { dismiss() }
        }
    }
}

private struct ViewerPage: View {
    /// Follows Dynamic Type instead of a fixed point size.
    @ScaledMetric(relativeTo: .largeTitle) private var iconSize: CGFloat = 64

    let store: LibraryStore
    let item: LibraryItem

    @Environment(\.displayScale) private var displayScale
    @State private var image: UIImage?
    @State private var session: VideoPlaybackSession?
    @State private var isStarting = false

    var body: some View {
        GeometryReader { proxy in
            ZStack {
                if let image {
                    ZoomableImage(image: image, isEnabled: !item.isVideo)
                        .accessibilityLabel(item.isVideo ? Text("Video") : Text("Photo"))
                } else {
                    ProgressView()
                }
                if item.isVideo {
                    Button(action: startPlayback) {
                        Image(systemName: "play.circle.fill")
                            .font(.system(size: iconSize))
                            .foregroundStyle(.white)
                            .shadow(radius: 6)
                    }
                    .disabled(isStarting)
                    .accessibilityLabel("Play video")
                }
            }
            .frame(width: proxy.size.width, height: proxy.size.height)
            .task(id: item.id) { await load(screen: proxy.size) }
        }
    }

    private func startPlayback() {
        guard session == nil, !isStarting else { return }
        isStarting = true
        Task {
            defer { isStarting = false }
            let started = await store.playbackSession(for: item)
            guard let started else { return }
            session = started
            NativeVideoPlayer.present(session: started) { stopPlayback() }
        }
    }

    private func stopPlayback() {
        session?.stop()
        session = nil
    }

    private func load(screen: CGSize) async {
        image = await store.thumbnail(for: item, large: true)
        guard !item.isVideo else { return }
        let side = Int(max(screen.width, screen.height) * displayScale)
        if let full = await store.original(for: item, maxPixel: max(side, 1)) { image = full }
    }
}

/// Native AVKit player presented modally in full screen (with its own close button), without
/// external playback, Picture-in-Picture or Now Playing. Playback ends when it is dismissed.
/// System player whose content (video and controls) lives in a secure canvas, so frames are
/// blank in screenshots, screen recordings and mirroring.
final class NativeVideoPlayer: AVPlayerViewController {
    private var onClose: (() -> Void)?
    private let secureField = SecureCanvasField()

    @MainActor
    static func present(session: VideoPlaybackSession, onClose: @escaping () -> Void) {
        guard let player = session.player else { return onClose() }
        present(player: player, onStart: { session.play() }, onClose: onClose)
    }

    @MainActor
    static func present(player: AVPlayer, onStart: @escaping () -> Void, onClose: @escaping () -> Void) {
        guard
            let root = UIApplication.shared.connectedScenes
                .compactMap({ ($0 as? UIWindowScene)?.keyWindow }).first?.rootViewController
        else {
            onClose()
            return
        }
        var top = root
        while let presented = top.presentedViewController { top = presented }
        let controller = NativeVideoPlayer()
        controller.onClose = onClose
        controller.player = player
        controller.allowsPictureInPicturePlayback = false
        controller.canStartPictureInPictureAutomaticallyFromInline = false
        controller.updatesNowPlayingInfoCenter = false
        controller.videoGravity = .resizeAspect
        controller.modalPresentationStyle = .fullScreen
        top.present(controller, animated: true) { onStart() }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        secureField.frame = view.bounds
        secureField.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(secureField)
        moveContentIntoCanvas()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        // The player may add views lazily; keep everything inside the canvas.
        moveContentIntoCanvas()
        secureField.frame = view.bounds
    }

    private func moveContentIntoCanvas() {
        for sub in view.subviews where sub !== secureField {
            sub.removeFromSuperview()
            sub.translatesAutoresizingMaskIntoConstraints = true
            sub.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            secureField.canvas.addSubview(sub)
            sub.frame = secureField.canvas.bounds
        }
        view.bringSubviewToFront(secureField)
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        guard isBeingDismissed || presentingViewController == nil else { return }
        player = nil
        onClose?()
        onClose = nil
    }
}

private struct ZoomableImage: View {
    let image: UIImage
    let isEnabled: Bool

    @State private var scale: CGFloat = 1
    @State private var baseScale: CGFloat = 1
    @State private var offset: CGSize = .zero
    @State private var baseOffset: CGSize = .zero

    var body: some View {
        SecureImage(image: image)
            .aspectRatio(image.size, contentMode: .fit)
            .scaleEffect(scale)
            .offset(offset)
            .gesture(
                MagnifyGesture()
                    .onChanged { scale = min(max(baseScale * $0.magnification, 1), 6) }
                    .onEnded { _ in
                        baseScale = scale
                        if scale == 1 { resetOffset() }
                    },
                including: isEnabled ? .all : .none
            )
            .gesture(
                DragGesture()
                    .onChanged {
                        offset = CGSize(
                            width: baseOffset.width + $0.translation.width,
                            height: baseOffset.height + $0.translation.height)
                    }
                    .onEnded { _ in baseOffset = offset },
                including: isEnabled && scale > 1 ? .all : .none
            )
            .onTapGesture(count: 2) {
                guard isEnabled else { return }
                withAnimation {
                    scale = scale > 1 ? 1 : 3
                    baseScale = scale
                    if scale == 1 { resetOffset() }
                }
            }
    }

    private func resetOffset() {
        offset = .zero
        baseOffset = .zero
    }
}

private struct InfoSheet: View {
    let item: LibraryItem
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                if let name = item.meta.filename { LabeledContent("Name", value: name) }
                LabeledContent("Date", value: item.date.formatted(date: .long, time: .shortened))
                if let size = item.meta.size {
                    LabeledContent("Size", value: size.formatted(.byteCount(style: .file)))
                }
                if let width = item.meta.width, let height = item.meta.height {
                    LabeledContent("Dimensions", value: "\(width) × \(height)")
                }
                if let seconds = item.durationSeconds {
                    LabeledContent(
                        "Duration", value: Duration.seconds(seconds).formatted(.time(pattern: .minuteSecond)))
                }
            }
            .navigationTitle("Info")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .presentationDetents([.medium])
    }
}

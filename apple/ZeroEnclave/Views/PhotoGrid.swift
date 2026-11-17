import SwiftUI

/// Long-press actions on a single item.
struct GridActions {
    let share: (LibraryItem) -> Void
    let addToAlbum: (LibraryItem) -> Void
    let delete: (LibraryItem) -> Void
}

/// Thumbnail grid shared by the gallery and the album detail.
struct PhotoGrid: View {
    let store: LibraryStore
    let items: [LibraryItem]
    let isSelecting: Bool
    @Binding var selection: Set<String>
    let onOpen: (LibraryItem) -> Void
    var actions: GridActions?

    var body: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 100), spacing: 2)], spacing: 2) {
                ForEach(items) { item in
                    GalleryCell(
                        store: store, item: item, isSelecting: isSelecting,
                        isSelected: selection.contains(item.id)
                    )
                    .onTapGesture {
                        if isSelecting {
                            if !selection.insert(item.id).inserted { selection.remove(item.id) }
                        } else {
                            onOpen(item)
                        }
                    }
                    .contextMenu {
                        if let actions, !isSelecting {
                            Button("Share…", systemImage: "square.and.arrow.up") { actions.share(item) }
                            Button("Add to album", systemImage: "rectangle.stack.badge.plus") {
                                actions.addToAlbum(item)
                            }
                            Button("Delete", systemImage: "trash", role: .destructive) { actions.delete(item) }
                        }
                    }
                }
            }
            if !items.isEmpty {
                summary
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 20)
                    .accessibilityAddTraits(.isSummaryElement)
            }
        }
    }

    /// Count below the grid, as in the Photos app.
    private var summary: Text {
        let videos = items.count { $0.isVideo }
        let photos = items.count - videos
        return switch (photos, videos) {
        case (_, 0): Text("^[\(photos) Photo](inflect: true)")
        case (0, _): Text("^[\(videos) Video](inflect: true)")
        default: Text("^[\(photos) Photo](inflect: true), ^[\(videos) Video](inflect: true)")
        }
    }
}

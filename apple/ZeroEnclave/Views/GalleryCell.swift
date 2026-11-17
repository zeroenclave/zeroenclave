import SwiftUI

struct GalleryCell: View {
    let store: LibraryStore
    let item: LibraryItem
    let isSelecting: Bool
    let isSelected: Bool

    @State private var image: UIImage?

    /// A trashed item hidden from All Photos (locked album) shows no preview in the trash.
    private var isLockedInTrash: Bool { item.trashedAt != nil && item.hiddenInAll }

    var body: some View {
        Color.secondary.opacity(0.15)
            .aspectRatio(1, contentMode: .fit)
            .overlay {
                if isLockedInTrash {
                    Image(systemName: "lock.fill")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                } else if let image {
                    SecureImage(image: image, contentMode: .scaleAspectFill)
                }
            }
            .clipped()
            .overlay(alignment: .bottomLeading) {
                if item.isVideo { videoBadge }
            }
            .overlay(alignment: .bottomTrailing) {
                if let days = item.daysLeftInTrash() { daysBadge(days) }
            }
            .overlay(alignment: .topTrailing) {
                if isSelecting {
                    Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                        .font(.title3)
                        .foregroundStyle(isSelected ? Theme.mint : .white)
                        .shadow(radius: 2)
                        .padding(6)
                }
            }
            .contentShape(.rect)
            .task(id: item.id) {
                guard !isLockedInTrash else { return }
                image = await store.thumbnail(for: item, large: false)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(label)
            .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : .isButton)
    }

    private var videoBadge: some View {
        HStack(spacing: 4) {
            Image(systemName: "video.fill")
            if let seconds = item.durationSeconds {
                Text(Duration.seconds(seconds), format: .time(pattern: .minuteSecond))
            }
        }
        .font(.caption2.weight(.semibold))
        .foregroundStyle(.white)
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .background(.black.opacity(0.55), in: .capsule)
        .padding(6)
    }

    private func daysBadge(_ days: Int) -> some View {
        Text("\(days) days")
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(.black.opacity(0.55), in: .capsule)
            .padding(6)
    }

    private var label: Text {
        let date = item.date.formatted(date: .abbreviated, time: .omitted)
        if item.isVideo { return Text("Video, \(date)") }
        return Text("Photo, \(date)")
    }
}

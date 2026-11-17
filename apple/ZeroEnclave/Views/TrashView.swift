import SwiftUI

/// Trash: browsing, restore and permanent delete are premium; items expire after 30 days.
struct TrashView: View {
    /// Follows Dynamic Type instead of a fixed point size.
    @ScaledMetric(relativeTo: .largeTitle) private var iconSize: CGFloat = 64

    let store: LibraryStore
    let gate: PremiumGate
    @Binding var isSelecting: Bool
    @Binding var selection: Set<String>
    let onOpen: (LibraryItem) -> Void

    @Environment(Entitlements.self) private var entitlements
    @State private var confirmDeleteSelected = false
    @State private var confirmEmpty = false

    var body: some View {
        Group {
            if store.trashed.isEmpty {
                ContentUnavailableView(
                    "No deleted items", systemImage: "trash",
                    description: Text("Deleted photos and videos stay here for 30 days."))
            } else if !canBrowse {
                lockedState
            } else {
                PhotoGrid(
                    store: store, items: store.trashed, isSelecting: isSelecting, selection: $selection,
                    onOpen: { item in if !item.hiddenInAll { onOpen(item) } })
                    .safeAreaInset(edge: .bottom) {
                        Text("Items are deleted permanently after 30 days.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .padding(.vertical, 8)
                            .frame(maxWidth: .infinity)
                            .background(.bar)
                    }
            }
        }
        .toolbar { toolbar }
        .confirmSheet(
            isPresented: $confirmDeleteSelected, systemImage: "trash",
            title: "Delete \(selection.count) items permanently?", message: "This cannot be undone.",
            actions: [
                ConfirmAction(title: "Delete permanently", role: .destructive) {
                    let ids = selection
                    Task {
                        _ = await store.deletePermanently(ids: ids)
                        endSelecting()
                    }
                }
            ]
        )
        .confirmSheet(
            isPresented: $confirmEmpty, systemImage: "trash",
            title: "Delete all items permanently?", message: "This cannot be undone.",
            actions: [
                ConfirmAction(title: "Delete permanently", role: .destructive) {
                    Task { _ = await store.emptyTrash() }
                }
            ]
        )
    }

    /// The whole trash is premium; without it items only expire.
    private var canBrowse: Bool { entitlements.isUnlocked(.trashRestore) }

    private var lockedState: some View {
        VStack(spacing: 20) {
            Image(systemName: "trash.circle.fill")
                .font(.system(size: iconSize))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(Theme.mint)
                .accessibilityHidden(true)
            Text("\(store.trashed.count) items in the Trash")
                .font(.title2.weight(.bold))
                .multilineTextAlignment(.center)
            Text("View, restore and delete items in the Trash with Premium. Items are deleted permanently after 30 days.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button { gate.require(.trashRestore) } label: {
                Label("Restore with Premium", systemImage: "sparkles").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .foregroundStyle(Theme.onAccent)
            .controlSize(.large)
        }
        .padding(24)
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        if isSelecting {
            ToolbarItem(placement: .primaryAction) {
                Button("Restore", systemImage: "arrow.uturn.backward", action: restoreSelected)
                    .disabled(selection.isEmpty)
                    .accessibilityLabel("Restore selected items")
            }
            ToolbarItem(placement: .primaryAction) {
                Button("Delete permanently", systemImage: "trash", role: .destructive) {
                    confirmDeleteSelected = true
                }
                .disabled(selection.isEmpty)
                .accessibilityLabel("Delete selected items permanently")
            }
            ToolbarItem(placement: .primaryAction) {
                Button("Done", action: endSelecting)
            }
        } else {
            // Hidden rather than disabled: an empty trash has nothing to act on.
            if canBrowse, !store.trashed.isEmpty {
                ToolbarItem(placement: .primaryAction) {
                    Button("Select") { isSelecting = true }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Empty", role: .destructive) { confirmEmpty = true }
                }
            }
        }
    }

    private func restoreSelected() {
        let ids = selection
        gate.perform(.trashRestore, entitlements: entitlements) {
            Task {
                _ = await store.restore(ids: ids)
                endSelecting()
            }
        }
    }

    private func endSelecting() {
        isSelecting = false
        selection = []
    }
}

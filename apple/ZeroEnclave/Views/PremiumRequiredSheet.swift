import SwiftUI

/// Shown when a locked premium feature is tapped: the premium page with that feature highlighted.
struct PremiumRequiredSheet: View {
    let feature: Feature?

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            PremiumView(highlight: feature)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Close") { dismiss() }
                    }
                }
        }
    }
}

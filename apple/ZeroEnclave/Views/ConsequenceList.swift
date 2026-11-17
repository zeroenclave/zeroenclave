import SwiftUI

/// One line in a destructive confirmation: what happens, with a symbol and tone.
struct Consequence: Identifiable {
    enum Tone { case destructive, warning, safe }

    let systemImage: String
    let text: LocalizedStringKey
    var tone = Tone.destructive

    var id: String { systemImage }
}

/// Short list of the effects of a destructive action, the first line emphasized.
struct ConsequenceList: View {
    let items: [Consequence]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                Label {
                    Text(item.text)
                        .font(index == 0 ? .headline : .body)
                } icon: {
                    Image(systemName: item.systemImage)
                        .foregroundStyle(color(item.tone))
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func color(_ tone: Consequence.Tone) -> Color {
        switch tone {
        case .destructive: .red
        case .warning: .orange
        case .safe: Theme.mint
        }
    }
}

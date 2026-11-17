import SwiftUI

struct StrengthMeter: View {
    let evaluation: PasswordPolicy.Evaluation
    /// False where a requirements checklist already shows the length.
    var showsLength = true

    private var label: LocalizedStringKey {
        switch evaluation.score {
        case 0, 1: "Weak"
        case 2: "Fair"
        case 3: "Good"
        default: "Strong"
        }
    }

    private var color: Color {
        switch evaluation.score {
        case 0, 1: .red
        case 2: .orange
        default: Theme.mint
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                ForEach(1...4, id: \.self) { step in
                    Capsule()
                        .fill(step <= evaluation.score ? color : Color.secondary.opacity(0.25))
                        .frame(height: 6)
                }
            }
            .accessibilityHidden(true)
            HStack {
                Text(label).font(.footnote.weight(.semibold))
                Spacer()
                if showsLength {
                    Text("\(evaluation.length) of \(PasswordPolicy.minLength) characters")
                        .font(.footnote)
                        .foregroundStyle(evaluation.meetsLength ? Color.secondary : Color.orange)
                }
            }
            Text("Use a passphrase of several unrelated words.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}

import SwiftUI

/// One button of a confirmation sheet.
struct ConfirmAction {
    let title: LocalizedStringKey
    var role: ButtonRole?
    let action: () -> Void
}

extension View {
    /// Bottom sheet that replaces the system dialog. Every action dismisses the sheet first, then runs.
    func confirmSheet(
        isPresented: Binding<Bool>, systemImage: String, title: LocalizedStringKey,
        message: LocalizedStringKey? = nil, actions: [ConfirmAction]
    ) -> some View {
        modifier(
            ConfirmSheetModifier(
                isPresented: isPresented, systemImage: systemImage, title: title, message: message,
                actions: actions))
    }

    /// Variant for dialogs that act on data: the actions are built from the presented item.
    func confirmSheet<Item: Identifiable>(
        item: Binding<Item?>, systemImage: String, title: LocalizedStringKey,
        message: LocalizedStringKey? = nil, actions: @escaping (Item) -> [ConfirmAction]
    ) -> some View {
        modifier(
            ConfirmItemSheetModifier(
                item: item, systemImage: systemImage, title: title, message: message,
                actions: actions))
    }
}

private struct ConfirmSheetModifier: ViewModifier {
    @Binding var isPresented: Bool
    let systemImage: String
    let title: LocalizedStringKey
    let message: LocalizedStringKey?
    let actions: [ConfirmAction]

    /// Runs after the dismissal, so an action may present or dismiss other views.
    @State private var pending: (() -> Void)?

    func body(content: Content) -> some View {
        content.sheet(
            isPresented: $isPresented,
            onDismiss: {
                let run = pending
                pending = nil
                run?()
            }
        ) {
            ConfirmSheetContent(
                systemImage: systemImage, title: title, message: message, actions: actions
            ) { action in
                pending = action?.action
                isPresented = false
            }
        }
    }
}

private struct ConfirmItemSheetModifier<Item: Identifiable>: ViewModifier {
    @Binding var item: Item?
    let systemImage: String
    let title: LocalizedStringKey
    let message: LocalizedStringKey?
    let actions: (Item) -> [ConfirmAction]

    @State private var pending: (() -> Void)?

    func body(content: Content) -> some View {
        content.sheet(
            item: $item,
            onDismiss: {
                let run = pending
                pending = nil
                run?()
            }
        ) { presented in
            ConfirmSheetContent(
                systemImage: systemImage, title: title, message: message, actions: actions(presented)
            ) { action in
                pending = action?.action
                item = nil
            }
        }
    }
}

private struct ConfirmSheetContent: View {
    let systemImage: String
    let title: LocalizedStringKey
    let message: LocalizedStringKey?
    let actions: [ConfirmAction]
    /// Called with the chosen action, or nil for Cancel.
    let onChoose: (ConfirmAction?) -> Void

    @State private var height: CGFloat = 320

    private var isDestructive: Bool { actions.contains { $0.role == .destructive } }
    private var tint: Color { isDestructive ? .red : Theme.mint }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: systemImage)
                .font(.title2)
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(tint)
                .frame(width: 56, height: 56)
                .background(tint.opacity(0.15), in: .circle)
                .accessibilityHidden(true)
            Text(title)
                .font(.title3.bold())
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if let message {
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(spacing: 10) {
                ForEach(actions.indices, id: \.self) { index in
                    let action = actions[index]
                    if action.role == .destructive {
                        Button(role: action.role) { onChoose(action) } label: {
                            Text(action.title).frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.glassProminent)
                        .foregroundStyle(Theme.onAccent)
                        .tint(.red)
                    } else {
                        Button(role: action.role) { onChoose(action) } label: {
                            Text(action.title).frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.glass)
                    }
                }
                Button(role: .cancel) { onChoose(nil) } label: {
                    Text("Cancel").frame(maxWidth: .infinity)
                }
                .buttonStyle(.glass)
            }
            .controlSize(.large)
        }
        .padding(24)
        // Report the ideal height, not the detent height, so text never truncates.
        .fixedSize(horizontal: false, vertical: true)
        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { height = $0 }
        .presentationDetents([.height(height)])
        .presentationDragIndicator(.visible)
    }
}

import SwiftUI

/// Six dots and a round number pad, like the iOS passcode screen. No system keyboard, so the
/// layout stays calm and the digits never reach autocorrection or the clipboard.
struct PinPad: View {
    /// `accepted` turns the dots green with a success tap, right before the vault opens.
    enum Feedback { case none, accepted }

    @Binding var pin: String
    /// Six for the unlock PIN, four for album codes.
    var length = UnlockPin.length
    var isDisabled = false
    /// Bumping this shakes the dots, e.g. after a mismatch.
    var shake = 0
    var feedback = Feedback.none
    let onComplete: (String) -> Void

    @ScaledMetric(relativeTo: .title) private var scaledKey: CGFloat = 78
    /// Grows with Dynamic Type but stays within the screen width.
    private var keySize: CGFloat { min(scaledKey, 92) }

    var body: some View {
        VStack(spacing: 44) {
            dots
            keypad
        }
        .sensoryFeedback(.error, trigger: shake)
        .sensoryFeedback(.success, trigger: feedback) { _, new in new == .accepted }
    }

    private var dotColor: Color { feedback == .accepted ? Theme.mint : Theme.ink }

    private var dots: some View {
        HStack(spacing: 20) {
            ForEach(0..<length, id: \.self) { index in
                Circle()
                    .fill(index < pin.count ? dotColor : Color.clear)
                    .overlay(Circle().stroke(dotColor.opacity(0.5), lineWidth: 1.5))
                    .frame(width: 14, height: 14)
                    .scaleEffect(feedback == .accepted ? 1.15 : 1)
            }
        }
        .animation(.spring(duration: 0.3), value: feedback)
        .modifier(Shake(trigger: CGFloat(shake)))
        .animation(.default, value: shake)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("PIN")
        .accessibilityValue(Text("\(pin.count) of \(length) digits entered"))
    }

    private var keypad: some View {
        Grid(horizontalSpacing: 28, verticalSpacing: 18) {
            ForEach([["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"]], id: \.self) { row in
                GridRow { ForEach(row, id: \.self) { digitKey($0) } }
            }
            GridRow {
                Color.clear.frame(width: keySize, height: keySize)
                digitKey("0")
                deleteKey
            }
        }
        .disabled(isDisabled)
    }

    private func digitKey(_ digit: String) -> some View {
        Button {
            guard pin.count < length else { return }
            pin += digit
            if pin.count == length { onComplete(pin) }
        } label: {
            Text(verbatim: digit)
                .font(.system(.title, design: .rounded).weight(.regular))
                .frame(width: keySize, height: keySize)
                .background(.fill.tertiary, in: .circle)
                .contentShape(.circle)
        }
        .buttonStyle(PinKeyStyle())
    }

    private var deleteKey: some View {
        Button {
            if !pin.isEmpty { pin.removeLast() }
        } label: {
            Image(systemName: "delete.left")
                .font(.title2)
                .frame(width: keySize, height: keySize)
                .contentShape(.circle)
        }
        .buttonStyle(PinKeyStyle())
        .opacity(pin.isEmpty ? 0 : 1)
        .accessibilityLabel("Delete")
    }
}

/// Keys darken while pressed and tick like the system keypad.
private struct PinKeyStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(Theme.ink)
            .opacity(configuration.isPressed ? 0.45 : 1)
            .sensoryFeedback(.selection, trigger: configuration.isPressed) { _, pressed in pressed }
    }
}

/// Horizontal shake; animates whenever `trigger` changes.
private struct Shake: GeometryEffect {
    var trigger: CGFloat
    var animatableData: CGFloat {
        get { trigger }
        set { trigger = newValue }
    }

    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: 10 * sin(trigger * .pi * 4), y: 0))
    }
}

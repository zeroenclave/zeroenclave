import SwiftUI

/// Album code in two pages: choose it, repeat it. A mismatch shakes and starts over.
struct AlbumCodeFlow: View {
    /// Shown under the title, e.g. the album name.
    var context: String?
    let onComplete: (String) async -> Bool

    @State private var confirming = false
    @State private var code = ""
    @State private var chosen = ""
    @State private var message: String?
    @State private var shake = 0
    @State private var feedback = PinPad.Feedback.none
    @State private var working = false

    var body: some View {
        VStack(spacing: 0) {
            FlowHeader(
                icon: "lock.rectangle.stack.fill",
                title: Text(confirming ? "Repeat the code" : "Choose a code"),
                subtitle: message ?? context ?? String(localized: "Four digits to open this album."),
                isError: message != nil)
            Spacer(minLength: 24)
            PinPad(
                pin: $code, length: AlbumCode.length, isDisabled: working, shake: shake, feedback: feedback,
                onComplete: entered)
                .id(confirming)
                .transition(
                    .asymmetric(
                        insertion: .move(edge: .trailing).combined(with: .opacity),
                        removal: .move(edge: .leading).combined(with: .opacity)))
            Spacer(minLength: 24)
            AlbumLockFooter()
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
                .padding(.bottom, 12)
        }
        .frame(maxWidth: .infinity)
        .animation(.snappy, value: confirming)
        .animation(.default, value: message)
    }

    private func entered(_ value: String) {
        Task {
            // Let the last dot fill before the page moves on.
            try? await Task.sleep(for: .milliseconds(150))
            if !confirming {
                chosen = value
                code = ""
                message = nil
                confirming = true
            } else if value == chosen {
                feedback = .accepted
                try? await Task.sleep(for: .milliseconds(350))
                working = true
                let saved = await onComplete(value)
                working = false
                if !saved {
                    feedback = .none
                    restart(String(localized: "The album could not be changed."))
                }
            } else {
                shake += 1
                restart(String(localized: "The codes do not match. Try again."))
            }
        }
    }

    private func restart(_ text: String) {
        code = ""
        chosen = ""
        message = text
        confirming = false
    }
}

/// Explains what the album code does and does not protect.
struct AlbumLockFooter: View {
    var body: some View {
        Text(
            "The code only hides this album inside the unlocked vault. Encryption is provided by the master password."
        )
    }
}

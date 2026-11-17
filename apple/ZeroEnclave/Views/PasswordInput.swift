import SwiftUI

/// Password entry in a rounded container with an optional show/hide button.
struct PasswordInput: View {
    let title: LocalizedStringKey
    @Binding var text: String
    var contentType: UITextContentType = .password
    /// Plain monospaced text field without the eye button, e.g. for recovery keys.
    var secure = true
    var onSubmit: (() -> Void)?
    var focus: FocusState<Bool>.Binding?

    @State private var isRevealed = false
    @FocusState private var ownFocus: Bool

    private var isFocused: FocusState<Bool>.Binding { focus ?? $ownFocus }

    var body: some View {
        HStack(spacing: 8) {
            // Mirrors the eye button so the centered text stays centered in the field.
            if secure { Color.clear.frame(width: 44, height: 44).accessibilityHidden(true) }
            field
                .focused(isFocused)
                .submitLabel(.go)
                .onSubmit { onSubmit?() }
            if secure {
                Button {
                    isRevealed.toggle()
                    isFocused.wrappedValue = true
                } label: {
                    Image(systemName: isRevealed ? "eye.slash" : "eye")
                        .foregroundStyle(.secondary)
                        .frame(width: 44, height: 44)
                        .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(isRevealed ? "Hide password" : "Show password")
            }
        }
        .padding(.horizontal, 16)
        .frame(minHeight: 52)
        .background(.fill.tertiary, in: .rect(cornerRadius: 16))
        .onDisappear { isRevealed = false }
    }

    @ViewBuilder
    private var field: some View {
        if !secure {
            TextField(title, text: $text)
                .font(.system(.body, design: .monospaced))
                .textInputAutocapitalization(.characters)
                .multilineTextAlignment(.center)
                .autocorrectionDisabled()
                .privacySensitive()
        } else if isRevealed {
            TextField(title, text: $text)
                .masterPasswordStyle()
                .textContentType(contentType)
        } else {
            SecureField(title, text: $text)
                .masterPasswordStyle()
                .textContentType(contentType)
        }
    }
}

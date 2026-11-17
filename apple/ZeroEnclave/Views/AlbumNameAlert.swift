import SwiftUI

extension View {
    /// Alert with a name field; `onConfirm` only receives a valid, trimmed name.
    func albumNameAlert(
        _ title: LocalizedStringKey, confirm: LocalizedStringKey, isPresented: Binding<Bool>,
        text: Binding<String>, onConfirm: @escaping (String) -> Void
    ) -> some View {
        alert(title, isPresented: isPresented) {
            TextField("Album name", text: text)
                .multilineTextAlignment(.center)
            Button("Cancel", role: .cancel) {}
            Button(confirm) {
                if let name = AlbumName.validated(text.wrappedValue) { onConfirm(name) }
            }
            .disabled(AlbumName.validated(text.wrappedValue) == nil)
        }
    }
}

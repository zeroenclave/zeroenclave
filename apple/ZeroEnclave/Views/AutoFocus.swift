import SwiftUI

extension View {
    /// Raises the keyboard once the view is on screen, and again whenever `id` changes.
    /// Focus set while a sheet or push transition is still running is dropped by SwiftUI,
    /// so this waits until the transition is over.
    func autoFocus<ID: Equatable>(_ focus: FocusState<Bool>.Binding, id: ID) -> some View {
        task(id: id) {
            try? await Task.sleep(for: .milliseconds(450))
            focus.wrappedValue = true
        }
    }

    func autoFocus(_ focus: FocusState<Bool>.Binding) -> some View {
        autoFocus(focus, id: 0)
    }
}

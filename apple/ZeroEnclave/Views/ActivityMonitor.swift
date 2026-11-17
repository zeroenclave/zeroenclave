import SwiftUI
import UIKit

extension View {
    /// Calls `action` on every touch in the window without taking part in gesture handling.
    /// A SwiftUI `simultaneousGesture` at the root delayed or swallowed taps on list rows.
    func onAnyTouch(_ action: @escaping () -> Void) -> some View {
        background(TouchObserverView(action: action).allowsHitTesting(false))
    }
}

private struct TouchObserverView: UIViewRepresentable {
    let action: () -> Void

    func makeUIView(context: Context) -> HostView {
        HostView(action: action)
    }

    func updateUIView(_ view: HostView, context: Context) {
        view.observer.action = action
    }

    static func dismantleUIView(_ view: HostView, coordinator: ()) {
        view.observer.view?.removeGestureRecognizer(view.observer)
    }

    /// Installs the observer on its window, so touches anywhere in the app count.
    final class HostView: UIView {
        let observer: TouchObserver

        init(action: @escaping () -> Void) {
            observer = TouchObserver(action: action)
            super.init(frame: .zero)
            isUserInteractionEnabled = false
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

        override func didMoveToWindow() {
            super.didMoveToWindow()
            observer.view?.removeGestureRecognizer(observer)
            window?.addGestureRecognizer(observer)
        }
    }
}

/// Fails on the first touch, so it never recognizes, delays or cancels anything.
final class TouchObserver: UIGestureRecognizer, UIGestureRecognizerDelegate {
    var action: () -> Void

    init(action: @escaping () -> Void) {
        self.action = action
        super.init(target: nil, action: nil)
        cancelsTouchesInView = false
        delaysTouchesBegan = false
        delaysTouchesEnded = false
        delegate = self
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        action()
        state = .failed
    }

    func gestureRecognizer(
        _ gestureRecognizer: UIGestureRecognizer,
        shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer
    ) -> Bool {
        true
    }
}

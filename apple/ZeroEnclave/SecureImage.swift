import SwiftUI
import UIKit

/// Shows an image that is visible on the device but blank in screenshots, screen
/// recordings and mirroring.
struct SecureImage: UIViewRepresentable {
    let image: UIImage
    var contentMode: UIView.ContentMode = .scaleAspectFit

    func makeUIView(context: Context) -> SecureImageView { SecureImageView() }

    func updateUIView(_ view: SecureImageView, context: Context) {
        view.imageView.image = image
        view.imageView.contentMode = contentMode
    }
}

/// A secure text entry field used only for its canvas: the system excludes the canvas
/// layer from captures, so anything placed in `canvas` is protected the same way.
final class SecureCanvasField: UITextField {
    private(set) var canvas: UIView = UIView()

    init() {
        super.init(frame: CGRect(x: 0, y: 0, width: 100, height: 100))
        isSecureTextEntry = true
        layoutIfNeeded()
        canvas = subviews.first { String(describing: type(of: $0)).contains("CanvasView") } ?? subviews.first ?? self
        canvas.subviews.forEach { $0.removeFromSuperview() }
    }

    required init?(coder: NSCoder) { nil }

    override var canBecomeFirstResponder: Bool { false }

    override func layoutSubviews() {
        super.layoutSubviews()
        if canvas !== self { canvas.frame = bounds }
        canvas.subviews.forEach { $0.frame = canvas.bounds }
    }
}

final class SecureImageView: UIView {
    let imageView = UIImageView()
    private let field = SecureCanvasField()

    override init(frame: CGRect) {
        super.init(frame: frame)
        isUserInteractionEnabled = false
        clipsToBounds = true
        field.isUserInteractionEnabled = false
        imageView.clipsToBounds = true
        field.canvas.addSubview(imageView)
        addSubview(field)
    }

    required init?(coder: NSCoder) { nil }

    override func layoutSubviews() {
        super.layoutSubviews()
        field.frame = bounds
    }
}

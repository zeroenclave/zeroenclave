import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// System camera for photos and videos; captures are never written to the photo library.
struct CameraPicker: UIViewControllerRepresentable {
    /// Called with the capture, or nil if the user cancelled.
    let onFinished: (CameraImportSource?) -> Void

    static var isAvailable: Bool { UIImagePickerController.isSourceTypeAvailable(.camera) }

    func makeUIViewController(context: Context) -> UIImagePickerController {
        let controller = UIImagePickerController()
        controller.sourceType = .camera
        controller.mediaTypes = [UTType.image.identifier, UTType.movie.identifier]
        controller.videoQuality = .typeHigh
        controller.allowsEditing = false
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ controller: UIImagePickerController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onFinished: onFinished) }

    final class Coordinator: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
        let onFinished: (CameraImportSource?) -> Void

        init(onFinished: @escaping (CameraImportSource?) -> Void) {
            self.onFinished = onFinished
        }

        func imagePickerController(
            _ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]
        ) {
            if let url = info[.mediaURL] as? URL {
                onFinished(CameraImportSource.adoptVideo(at: url).map { CameraImportSource(.video($0)) })
            } else if let image = info[.originalImage] as? UIImage {
                onFinished(CameraImportSource(.photo(image)))
            } else {
                onFinished(nil)
            }
        }

        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            onFinished(nil)
        }
    }
}

import Foundation
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

/// Result handed to `loadFileRepresentation`; guards the work task against cancellation races.
private final class WorkBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<Void, Never>?
    private var cancelled = false
    var result: Result<T, Error> = .failure(CancellationError())

    func set(_ task: Task<Void, Never>) {
        lock.lock()
        defer { lock.unlock() }
        self.task = task
        if cancelled { task.cancel() }
    }

    func cancel() {
        lock.lock()
        defer { lock.unlock() }
        cancelled = true
        task?.cancel()
    }
}

/// A PHPicker result. The system-provided temp file is only read inside `withFile`, then the system deletes it.
struct PickerImportSource: ImportSource, @unchecked Sendable {
    private let provider: NSItemProvider
    let assetIdentifier: String?

    init(_ result: PHPickerResult) {
        provider = result.itemProvider
        assetIdentifier = result.assetIdentifier
    }

    var suggestedName: String? { provider.suggestedName }

    func withFile<T: Sendable>(
        _ body: @escaping @Sendable (URL, UTType) async throws -> T
    ) async throws -> T {
        guard
            let identifier = provider.registeredTypeIdentifiers.first(where: {
                guard let type = UTType($0) else { return false }
                return type.conforms(to: .image) || type.conforms(to: .movie)
            }), let type = UTType(identifier)
        else { throw ImportError.unsupported }

        let box = WorkBox<T>()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                _ = provider.loadFileRepresentation(forTypeIdentifier: identifier) { url, error in
                    guard let url else {
                        continuation.resume(throwing: error ?? ImportError.unsupported)
                        return
                    }
                    // The file is removed when this handler returns, so the work finishes here.
                    let done = DispatchSemaphore(value: 0)
                    box.set(
                        Task {
                            do { box.result = .success(try await body(url, type)) } catch {
                                box.result = .failure(error)
                            }
                            done.signal()
                        })
                    done.wait()
                    continuation.resume(with: box.result)
                }
            }
        } onCancel: {
            box.cancel()
        }
    }
}

/// Photo picker limited to images and videos; the library is only attached to receive asset identifiers.
struct PhotoPicker: UIViewControllerRepresentable {
    let onPicked: ([PickerImportSource]) -> Void

    func makeUIViewController(context: Context) -> PHPickerViewController {
        var configuration = PHPickerConfiguration(photoLibrary: .shared())
        configuration.selectionLimit = 0
        configuration.filter = .any(of: [.images, .videos])
        configuration.preferredAssetRepresentationMode = .current
        let controller = PHPickerViewController(configuration: configuration)
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ controller: PHPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onPicked: onPicked) }

    final class Coordinator: NSObject, PHPickerViewControllerDelegate {
        let onPicked: ([PickerImportSource]) -> Void

        init(onPicked: @escaping ([PickerImportSource]) -> Void) {
            self.onPicked = onPicked
        }

        func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
            onPicked(results.map(PickerImportSource.init))
        }
    }
}

/// Deletes originals from the photo library; iOS keeps them in "Recently Deleted" for 30 days.
enum PhotoLibraryDeleter {
    static func delete(assetIdentifiers: [String]) async -> Bool {
        guard !assetIdentifiers.isEmpty else { return true }
        let status = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
        guard status == .authorized || status == .limited else { return false }
        do {
            try await PHPhotoLibrary.shared().performChanges {
                let assets = PHAsset.fetchAssets(withLocalIdentifiers: assetIdentifiers, options: nil)
                PHAssetChangeRequest.deleteAssets(assets)
            }
            return true
        } catch {
            return false
        }
    }
}

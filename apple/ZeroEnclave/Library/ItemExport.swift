import Photos
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Single-item export of a decrypted original. The plaintext leaves the vault only on the
/// user's request: into the photo library or into a temporary file for the share sheet.
enum ItemExport {
    enum Failure: Error { case denied, failed }

    /// File name for the exported original, with an extension derived from the MIME type.
    static func fileName(for item: LibraryItem) -> String {
        let fallback = item.isVideo ? "Video" : "Photo"
        var name = TemporaryFiles.safeName(item.meta.filename, fallback: fallback)
        if (name as NSString).pathExtension.isEmpty,
            let ext = item.meta.mime.flatMap({ UTType(mimeType: $0)?.preferredFilenameExtension })
        {
            name += "." + ext
        }
        return name
    }

    /// Writes the data to a fresh tmp directory; the caller removes it with `TemporaryFiles.remove`.
    static func writeTemporary(_ data: Data, name: String) throws -> URL {
        let dir = try TemporaryFiles.makeDirectory()
        let url = dir.appending(path: name, directoryHint: .notDirectory)
        do {
            try data.write(to: url, options: [.completeFileProtection])
        } catch {
            TemporaryFiles.remove(url)
            throw error
        }
        return url
    }

    /// Adds the original to the photo library (add-only access). Videos go through a tmp file.
    static func saveToPhotos(_ data: Data, item: LibraryItem) async throws {
        let status = await PHPhotoLibrary.requestAuthorization(for: .addOnly)
        guard status == .authorized || status == .limited else { throw Failure.denied }
        let name = fileName(for: item)
        let options = PHAssetResourceCreationOptions()
        options.originalFilename = name
        if let mime = item.meta.mime { options.uniformTypeIdentifier = UTType(mimeType: mime)?.identifier }
        var tempURL: URL?
        defer { TemporaryFiles.remove(tempURL) }
        if item.isVideo {
            tempURL = try writeTemporary(data, name: name)
        }
        let videoURL = tempURL
        do {
            try await PHPhotoLibrary.shared().performChanges {
                let request = PHAssetCreationRequest.forAsset()
                if let videoURL {
                    request.addResource(with: .video, fileURL: videoURL, options: options)
                } else {
                    request.addResource(with: .photo, data: data, options: options)
                }
            }
        } catch {
            throw Failure.failed
        }
    }
}

/// A decrypted file in tmp that is offered to the share sheet.
struct SharedFile: Identifiable {
    let id = UUID()
    let url: URL
}

/// System share sheet for one file; `onDone` runs when it is dismissed.
struct ShareSheet: UIViewControllerRepresentable {
    let url: URL
    let onDone: () -> Void

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        controller.completionWithItemsHandler = { _, _, _, _ in onDone() }
        return controller
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

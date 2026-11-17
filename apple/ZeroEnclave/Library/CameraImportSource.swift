import UIKit
import UniformTypeIdentifiers

/// A capture from the in-app camera. The temp file lives only inside `withFile`.
struct CameraImportSource: ImportSource, @unchecked Sendable {
    enum Capture {
        case photo(UIImage)
        case video(URL)
    }

    private let capture: Capture

    init(_ capture: Capture) { self.capture = capture }

    /// Temp files of camera captures; removed after import, on lock and at launch.
    static let prefix = "ze-cam-"

    /// Moves the camera's video into a protected, prefixed temp file so leftovers can be found.
    static func adoptVideo(at url: URL) -> URL? {
        let target = FileManager.default.temporaryDirectory
            .appendingPathComponent(prefix + UUID().uuidString)
            .appendingPathExtension(url.pathExtension.isEmpty ? "mov" : url.pathExtension)
        do {
            try FileManager.default.moveItem(at: url, to: target)
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete], ofItemAtPath: target.path)
            return target
        } catch {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(at: target)
            return nil
        }
    }

    /// Drops captures that were never imported (vault locked, app killed).
    static func removeStale() {
        let tmp = FileManager.default.temporaryDirectory
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? []
        for name in entries where name.hasPrefix(prefix) {
            try? FileManager.default.removeItem(at: tmp.appendingPathComponent(name))
        }
    }

    var suggestedName: String? { "Camera" }
    var assetIdentifier: String? { nil }

    func withFile<T: Sendable>(
        _ body: @escaping @Sendable (URL, UTType) async throws -> T
    ) async throws -> T {
        switch capture {
        case .photo(let image):
            let type: UTType
            let data: Data
            if let heic = image.heicData() {
                type = .heic
                data = heic
            } else if let jpeg = image.jpegData(compressionQuality: 0.95) {
                type = .jpeg
                data = jpeg
            } else {
                throw ImportError.unsupported
            }
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent(Self.prefix + UUID().uuidString)
                .appendingPathExtension(type.preferredFilenameExtension ?? "img")
            defer { try? FileManager.default.removeItem(at: url) }
            try data.write(to: url, options: [.completeFileProtection, .atomic])
            return try await body(url, type)
        case .video(let url):
            defer { try? FileManager.default.removeItem(at: url) }
            let type = UTType(filenameExtension: url.pathExtension) ?? .quickTimeMovie
            return try await body(url, type.conforms(to: .movie) ? type : .quickTimeMovie)
        }
    }
}

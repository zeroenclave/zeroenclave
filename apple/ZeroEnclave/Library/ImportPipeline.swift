import AVFoundation
import Foundation
import ImageIO
import UniformTypeIdentifiers
import ZeroEnclaveCore

enum ImportError: Error {
    case unsupported
    /// The vault was locked while the import ran.
    case locked
}

/// A picked file whose bytes are only valid inside `withFile`.
protocol ImportSource: Sendable {
    var suggestedName: String? { get }
    /// Photo library identifier, used only to delete the original after import.
    var assetIdentifier: String? { get }
    func withFile<T: Sendable>(
        _ body: @escaping @Sendable (URL, UTType) async throws -> T
    ) async throws -> T
}

/// Encrypts one source into the vault: original, thumb_small and thumb_large.
struct ImportPipeline: Sendable {
    static let blockSize = 1 << 20

    let handle: VaultHandle

    func importItem(_ source: any ImportSource) async throws -> String {
        let name = source.suggestedName
        return try await source.withFile { url, type in
            try await importFile(at: url, type: type, name: name)
        }
    }

    private func importFile(at url: URL, type: UTType, name: String?) async throws -> String {
        let kind: ItemKind
        var meta = ItemMeta(
            filename: name, created: nil, imported: Self.nowMs(), mime: type.preferredMIMEType,
            width: nil, height: nil, duration: nil, size: nil)
        let small: Data
        let large: Data
        if type.conforms(to: .movie) {
            kind = .video
            try await Self.fillVideoMeta(&meta, url: url)
            small = try await ThumbnailGenerator.jpeg(
                videoAt: url, maxPixel: ThumbnailGenerator.smallSide)
            large = try await ThumbnailGenerator.jpeg(
                videoAt: url, maxPixel: ThumbnailGenerator.largeSide)
        } else if type.conforms(to: .image) {
            // TODO: Live Photos are imported as stills; store the paired video as ObjectRole.pairedVideo.
            kind = .photo
            guard let source = CGImageSourceCreateWithURL(url as CFURL, nil) else {
                throw ThumbnailError.unreadable
            }
            Self.fillImageMeta(&meta, source: source)
            small = try ThumbnailGenerator.jpeg(from: source, maxPixel: ThumbnailGenerator.smallSide)
            large = try ThumbnailGenerator.jpeg(from: source, maxPixel: ThumbnailGenerator.largeSide)
        } else {
            throw ImportError.unsupported
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        meta.size = (attributes[.size] as? NSNumber)?.uint64Value

        do {
            let session = try handle.beginImport(kind: kind, meta: meta)
            do {
                try Task.checkCancellation()
                try Self.stream(file: url, into: try session.addObject(role: .original))
                try Self.write(small, into: try session.addObject(role: .thumbSmall))
                try Self.write(large, into: try session.addObject(role: .thumbLarge))
                try Task.checkCancellation()
                return try session.commit()
            } catch {
                session.abort()
                throw error
            }
        } catch let error as ZeError {
            if case .Locked = error { throw ImportError.locked }
            throw error
        }
    }

    private static func stream(file url: URL, into writer: ObjectWriterHandle) throws {
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        while let block = try input.read(upToCount: blockSize), !block.isEmpty {
            try Task.checkCancellation()
            try writer.write(data: block)
        }
        try writer.finish()
    }

    private static func write(_ data: Data, into writer: ObjectWriterHandle) throws {
        var offset = 0
        while offset < data.count {
            let end = min(offset + blockSize, data.count)
            try writer.write(data: data.subdata(in: offset..<end))
            offset = end
        }
        try writer.finish()
    }

    // MARK: Metadata

    private static func nowMs() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded())
    }

    private static func fillImageMeta(_ meta: inout ItemMeta, source: CGImageSource) {
        guard let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any] else {
            return
        }
        var width = props[kCGImagePropertyPixelWidth] as? UInt64
        var height = props[kCGImagePropertyPixelHeight] as? UInt64
        // Orientations 5...8 are rotated by 90 degrees.
        if let orientation = props[kCGImagePropertyOrientation] as? Int, orientation >= 5 {
            swap(&width, &height)
        }
        meta.width = width
        meta.height = height
        let exif = props[kCGImagePropertyExifDictionary] as? [CFString: Any]
        if let text = exif?[kCGImagePropertyExifDateTimeOriginal] as? String {
            let offset = exif?[kCGImagePropertyExifOffsetTimeOriginal] as? String
            meta.created = exifDate(text, offset: offset).map {
                Int64(($0.timeIntervalSince1970 * 1000).rounded())
            }
        }
    }

    private static func fillVideoMeta(_ meta: inout ItemMeta, url: URL) async throws {
        let asset = AVURLAsset(url: url)
        let duration = try await asset.load(.duration).seconds
        if duration.isFinite, duration >= 0 { meta.duration = UInt64((duration * 1000).rounded()) }
        if let item = try await asset.load(.creationDate),
            let date = try await item.load(.dateValue)
        {
            meta.created = Int64((date.timeIntervalSince1970 * 1000).rounded())
        }
        if let track = try await asset.loadTracks(withMediaType: .video).first {
            let (size, transform) = try await track.load(.naturalSize, .preferredTransform)
            let rect = CGRect(origin: .zero, size: size).applying(transform)
            meta.width = UInt64(abs(rect.width).rounded())
            meta.height = UInt64(abs(rect.height).rounded())
        }
    }

    /// Parses `yyyy:MM:dd HH:mm:ss` with an optional `+HH:mm` offset; falls back to the local zone.
    static func exifDate(_ text: String, offset: String?) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy:MM:dd HH:mm:ss"
        formatter.timeZone = offset.flatMap(timeZone(offset:)) ?? .current
        return formatter.date(from: text)
    }

    private static func timeZone(offset: String) -> TimeZone? {
        let parts = offset.split(separator: ":")
        guard parts.count == 2, let hours = Int(parts[0]), let minutes = Int(parts[1]),
            abs(hours) <= 14, (0..<60).contains(minutes)
        else { return nil }
        let sign = offset.hasPrefix("-") ? -1 : 1
        return TimeZone(secondsFromGMT: hours * 3600 + sign * minutes * 60)
    }
}

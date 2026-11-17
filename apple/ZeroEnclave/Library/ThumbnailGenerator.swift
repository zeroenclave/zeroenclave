import AVFoundation
import ImageIO
import UniformTypeIdentifiers

enum ThumbnailError: Error {
    case unreadable
    case encodingFailed
}

/// Builds JPEG thumbnails in memory. Only pixel data is encoded, so GPS and EXIF never reach the output.
enum ThumbnailGenerator {
    static let smallSide = 256
    static let largeSide = 1536
    static let jpegQuality = 0.8

    static func jpeg(from source: CGImageSource, maxPixel: Int) throws -> Data {
        var side = maxPixel
        // Never upscale: ImageIO may enlarge small sources otherwise.
        if let longest = longestSide(of: source) { side = min(side, longest) }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: side,
        ]
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else {
            throw ThumbnailError.unreadable
        }
        return try encode(image)
    }

    static func jpeg(imageAt url: URL, maxPixel: Int) throws -> Data {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil) else {
            throw ThumbnailError.unreadable
        }
        return try jpeg(from: source, maxPixel: maxPixel)
    }

    /// Poster frame of a video, taken from the file before it is released.
    static func jpeg(videoAt url: URL, maxPixel: Int) async throws -> Data {
        let asset = AVURLAsset(url: url)
        let generator = AVAssetImageGenerator(asset: asset)
        generator.appliesPreferredTrackTransform = true
        generator.maximumSize = CGSize(width: maxPixel, height: maxPixel)
        let duration = (try? await asset.load(.duration).seconds) ?? 0
        let seconds = duration.isFinite ? min(1, max(0, duration / 2)) : 0
        let time = CMTime(seconds: seconds, preferredTimescale: 600)
        do {
            return try encode(try await generator.image(at: time).image)
        } catch is ThumbnailError {
            throw ThumbnailError.encodingFailed
        } catch {
            throw ThumbnailError.unreadable
        }
    }

    static func encode(_ image: CGImage) throws -> Data {
        let data = NSMutableData()
        guard
            let destination = CGImageDestinationCreateWithData(
                data, UTType.jpeg.identifier as CFString, 1, nil)
        else { throw ThumbnailError.encodingFailed }
        let options = [kCGImageDestinationLossyCompressionQuality: jpegQuality]
        CGImageDestinationAddImage(destination, image, options as CFDictionary)
        guard CGImageDestinationFinalize(destination) else { throw ThumbnailError.encodingFailed }
        return data as Data
    }

    private static func longestSide(of source: CGImageSource) -> Int? {
        guard let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
            let width = props[kCGImagePropertyPixelWidth] as? Int,
            let height = props[kCGImagePropertyPixelHeight] as? Int
        else { return nil }
        return max(width, height)
    }
}

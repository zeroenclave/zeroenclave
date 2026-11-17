import ImageIO
import Testing
import UIKit
import UniformTypeIdentifiers
import ZeroEnclaveCore

@testable import ZeroEnclave

/// Reads a local file instead of a PHPicker result.
private struct FileImportSource: ImportSource {
    let url: URL
    var suggestedName: String? { "synthetic" }
    var assetIdentifier: String? { nil }

    func withFile<T: Sendable>(
        _ body: @escaping @Sendable (URL, UTType) async throws -> T
    ) async throws -> T {
        try await body(url, .jpeg)
    }
}

private enum Fixture {
    /// JPEG with a GPS dictionary, so the tests can prove thumbnails drop it.
    static func jpeg(width: Int, height: Int) -> Data {
        let context = CGContext(
            data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        context.setFillColor(UIColor.systemTeal.cgColor)
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        let data = NSMutableData()
        let destination = CGImageDestinationCreateWithData(
            data, UTType.jpeg.identifier as CFString, 1, nil)!
        let properties: [CFString: Any] = [
            kCGImagePropertyGPSDictionary: [
                kCGImagePropertyGPSLatitude: 48.0, kCGImagePropertyGPSLatitudeRef: "N",
            ],
            kCGImagePropertyExifDictionary: [
                kCGImagePropertyExifDateTimeOriginal: "2024:03:05 10:20:30"
            ],
        ]
        CGImageDestinationAddImage(destination, context.makeImage()!, properties as CFDictionary)
        CGImageDestinationFinalize(destination)
        return data as Data
    }

    static func write(_ data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "ze-test-\(UUID().uuidString).jpg")
        try data.write(to: url)
        return url
    }
}

@MainActor
struct LibraryTests {
    private let defaults = UserDefaults(suiteName: "ze-test-\(UUID().uuidString)")!

    private func unlockedService() async -> VaultService {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "ze-test-\(UUID().uuidString)", directoryHint: .isDirectory)
            .appending(path: "Vault", directoryHint: .isDirectory)
        let service = VaultService(root: root, defaults: defaults, calibrate: { kdfDefault() })
        service.beginOnboarding()
        _ = await service.createVault(password: "synthetic test passphrase")
        service.acknowledgeRecoveryKey()
        service.finishOnboarding()
        return service
    }

    private func handle(of service: VaultService) throws -> VaultHandle {
        guard case .unlocked(let handle) = service.state else { throw ThumbnailError.unreadable }
        return handle
    }

    @Test func thumbnailHasExpectedSizeAndNoGps() throws {
        let source = CGImageSourceCreateWithData(Fixture.jpeg(width: 800, height: 400) as CFData, nil)!
        let jpeg = try ThumbnailGenerator.jpeg(from: source, maxPixel: ThumbnailGenerator.smallSide)
        let output = CGImageSourceCreateWithData(jpeg as CFData, nil)!
        let props = CGImageSourceCopyPropertiesAtIndex(output, 0, nil) as! [CFString: Any]
        #expect(props[kCGImagePropertyPixelWidth] as? Int == 256)
        #expect(props[kCGImagePropertyPixelHeight] as? Int == 128)
        #expect(props[kCGImagePropertyGPSDictionary] == nil)
        let exif = props[kCGImagePropertyExifDictionary] as? [CFString: Any]
        #expect(exif?[kCGImagePropertyExifDateTimeOriginal] == nil)
        #expect(CGImageSourceGetType(output) as String? == UTType.jpeg.identifier)
    }

    @Test func thumbnailDoesNotUpscale() throws {
        let source = CGImageSourceCreateWithData(Fixture.jpeg(width: 100, height: 60) as CFData, nil)!
        let jpeg = try ThumbnailGenerator.jpeg(from: source, maxPixel: ThumbnailGenerator.largeSide)
        let props = CGImageSourceCopyPropertiesAtIndex(
            CGImageSourceCreateWithData(jpeg as CFData, nil)!, 0, nil) as! [CFString: Any]
        #expect(props[kCGImagePropertyPixelWidth] as? Int == 100)
    }

    @Test func importStoresOriginalAndThumbnails() async throws {
        let service = await unlockedService()
        let original = Fixture.jpeg(width: 640, height: 480)
        let url = try Fixture.write(original)
        defer { try? FileManager.default.removeItem(at: url) }

        let handle = try handle(of: service)
        _ = try await ImportPipeline(handle: handle).importItem(FileImportSource(url: url))

        let items = try handle.items()
        #expect(items.count == 1)
        let item = try #require(items.first)
        #expect(item.kind == .photo)
        #expect(item.meta.filename == "synthetic")
        #expect(item.meta.width == 640)
        #expect(item.meta.height == 480)
        #expect(item.meta.size == UInt64(original.count))
        #expect(item.meta.mime == "image/jpeg")
        #expect(item.meta.created != nil)
        #expect(Set(item.objects.map(\.role)) == [.original, .thumbSmall, .thumbLarge])
        let originalID = try #require(item.objects.first { $0.role == .original }?.objectId)
        #expect(try handle.openObject(objectId: originalID).readAll() == original)
    }

    @Test func lockClearsImageCache() async {
        let service = await unlockedService()
        service.imageCache.insert(UIImage(), forKey: "k")
        #expect(service.imageCache.image(forKey: "k") != nil)
        service.lock()
        #expect(service.imageCache.image(forKey: "k") == nil)
    }

    @Test func deleteRemovesItem() async throws {
        let service = await unlockedService()
        let url = try Fixture.write(Fixture.jpeg(width: 64, height: 64))
        defer { try? FileManager.default.removeItem(at: url) }
        _ = try await ImportPipeline(handle: try handle(of: service))
            .importItem(FileImportSource(url: url))

        let store = LibraryStore(vault: service)
        await store.reload()
        let item = try #require(store.items.first)
        #expect(await store.thumbnail(for: item, large: false) != nil)
        #expect(await store.deletePermanently(ids: [item.id]))
        #expect(store.items.isEmpty)
    }

    @Test func importOnLockedVaultFailsAsLocked() async throws {
        let service = await unlockedService()
        let handle = try handle(of: service)
        let url = try Fixture.write(Fixture.jpeg(width: 64, height: 64))
        defer { try? FileManager.default.removeItem(at: url) }
        service.lock()
        await #expect(throws: ImportError.self) {
            _ = try await ImportPipeline(handle: handle).importItem(FileImportSource(url: url))
        }
    }
}

import Foundation
import Testing
import UIKit

@testable import ZeroEnclave

struct CameraImportSourceTests {
    private struct Failure: Error {}

    private static func image() -> UIImage {
        UIGraphicsImageRenderer(size: CGSize(width: 8, height: 8)).image { context in
            UIColor.red.setFill()
            context.fill(CGRect(x: 0, y: 0, width: 8, height: 8))
        }
    }

    @Test func photoTempFileIsDeletedAfterBody() async throws {
        let source = CameraImportSource(.photo(Self.image()))
        let (url, existedInside) = try await source.withFile { url, type in
            #expect(type.conforms(to: .image))
            return (url, FileManager.default.fileExists(atPath: url.path))
        }
        #expect(existedInside)
        #expect(!FileManager.default.fileExists(atPath: url.path))
        #expect(source.assetIdentifier == nil)
    }

    @Test func photoTempFileIsDeletedWhenBodyThrows() async {
        let source = CameraImportSource(.photo(Self.image()))
        let box = URLBox()
        await #expect(throws: Failure.self) {
            try await source.withFile { url, _ in
                box.url = url
                throw Failure()
            } as Void
        }
        #expect(box.url != nil)
        #expect(box.url.map { !FileManager.default.fileExists(atPath: $0.path) } == true)
    }

    @Test func videoFileIsDeletedAfterBody() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString).mov")
        try Data([0]).write(to: url)
        let source = CameraImportSource(.video(url))
        try await source.withFile { _, type in
            #expect(type.conforms(to: .movie))
        }
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }
}

private final class URLBox: @unchecked Sendable {
    var url: URL?
}

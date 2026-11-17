import AVFoundation
import Testing
import UIKit
import ZeroEnclaveCore

@testable import ZeroEnclave

private final class FakeReader: RangeReader, @unchecked Sendable {
    let data: Data
    private let lock = NSLock()
    private var reads: [(offset: UInt64, len: UInt32)] = []
    private var failure: ZeError?

    init(data: Data) { self.data = data }

    var plaintextLength: UInt64 { UInt64(data.count) }
    var readLog: [(offset: UInt64, len: UInt32)] { lock.withLock { reads } }
    func fail(with error: ZeError) { lock.withLock { failure = error } }

    func readRange(offset: UInt64, len: UInt32) throws -> Data {
        try lock.withLock {
            if let failure { throw failure }
            reads.append((offset, len))
        }
        return data.subdata(in: Int(offset)..<Int(offset) + Int(len))
    }
}

private final class FakeRequest: VideoLoadingRequest, @unchecked Sendable {
    private let lock = NSLock()
    private let done = DispatchSemaphore(value: 0)
    private var cancelled = false
    private var received = Data()
    private var slices = 0
    private var outcome: Result<Void, Error>?
    private var info: (type: String, length: Int64)?

    let wantsContentInformation: Bool
    let dataRange: (offset: Int64, length: Int64?)?
    var onRespond: (@Sendable (Int) -> Void)?

    init(info: Bool = false, range: (offset: Int64, length: Int64?)? = nil) {
        wantsContentInformation = info
        dataRange = range
    }

    var requestKey: ObjectIdentifier { ObjectIdentifier(self) }
    var isCancelled: Bool { lock.withLock { cancelled } }
    func cancel() { lock.withLock { cancelled = true } }
    var bytes: Data { lock.withLock { received } }
    var contentInfo: (type: String, length: Int64)? { lock.withLock { info } }
    var result: Result<Void, Error>? { lock.withLock { outcome } }

    func fillContentInformation(contentType: String, length: Int64) {
        lock.withLock { info = (contentType, length) }
    }

    func respond(with data: Data) {
        let count = lock.withLock { () -> Int in
            received.append(data)
            slices += 1
            return slices
        }
        onRespond?(count)
    }

    func finish() { complete(.success(())) }
    func finish(with error: Error) { complete(.failure(error)) }

    private func complete(_ value: Result<Void, Error>) {
        lock.withLock { outcome = value }
        done.signal()
    }

    func waitUntilFinished() -> Bool { done.wait(timeout: .now() + 10) == .success }
}

private func pattern(_ count: Int) -> Data {
    Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ ($0 >> 8)) })
}

struct EncryptedVideoLoaderTests {
    private let slice = Int(EncryptedVideoLoader.sliceSize)

    @Test func contentInformation() {
        let reader = FakeReader(data: pattern(1000))
        let loader = EncryptedVideoLoader(reader: reader, mime: "video/mp4")
        let request = FakeRequest(info: true)
        loader.handle(request)
        #expect(request.waitUntilFinished())
        #expect(request.contentInfo?.length == 1000)
        #expect(request.contentInfo?.type == "public.mpeg-4")
        #expect(request.result.map { if case .success = $0 { true } else { false } } == true)
    }

    @Test func unknownMimeFallsBackToQuickTime() {
        let loader = EncryptedVideoLoader(reader: FakeReader(data: pattern(10)), mime: "image/jpeg")
        let request = FakeRequest(info: true)
        loader.handle(request)
        #expect(request.waitUntilFinished())
        #expect(request.contentInfo?.type == "com.apple.quicktime-movie")
    }

    @Test func rangedRequestAcrossSliceBoundaries() {
        let data = pattern(slice * 3 + 123)
        let reader = FakeReader(data: data)
        let loader = EncryptedVideoLoader(reader: reader, mime: nil)
        let offset = slice - 10
        let length = slice * 2 + 50
        let request = FakeRequest(range: (Int64(offset), Int64(length)))
        loader.handle(request)
        #expect(request.waitUntilFinished())
        #expect(request.bytes == data.subdata(in: offset..<offset + length))
        #expect(reader.readLog.allSatisfy { $0.len <= UInt32(slice) })
        #expect(reader.readLog.count == 3)
    }

    @Test func requestToEndOfResource() {
        let data = pattern(slice + 77)
        let loader = EncryptedVideoLoader(reader: FakeReader(data: data), mime: nil)
        let request = FakeRequest(range: (5, nil))
        loader.handle(request)
        #expect(request.waitUntilFinished())
        #expect(request.bytes == data.subdata(in: 5..<data.count))
    }

    @Test func overlongRequestIsClampedToResource() {
        let data = pattern(100)
        let loader = EncryptedVideoLoader(reader: FakeReader(data: data), mime: nil)
        let request = FakeRequest(range: (90, 1_000_000))
        loader.handle(request)
        #expect(request.waitUntilFinished())
        #expect(request.bytes == data.subdata(in: 90..<100))
    }

    @Test func cancellationStopsFurtherReads() {
        let reader = FakeReader(data: pattern(slice * 5))
        let loader = EncryptedVideoLoader(reader: reader, mime: nil)
        let request = FakeRequest(range: (0, nil))
        request.onRespond = { [unowned request] _ in request.cancel() }
        loader.handle(request)
        for _ in 0..<200 where loader.pendingCount > 0 { Thread.sleep(forTimeInterval: 0.01) }
        #expect(loader.pendingCount == 0)
        #expect(reader.readLog.count == 1)
        #expect(request.result == nil)
    }

    @Test func lockedReaderFinishesWithError() {
        let reader = FakeReader(data: pattern(slice * 2))
        reader.fail(with: .Locked)
        let loader = EncryptedVideoLoader(reader: reader, mime: nil)
        let request = FakeRequest(range: (0, nil))
        loader.handle(request)
        #expect(request.waitUntilFinished())
        guard case .failure(let error)? = request.result else {
            Issue.record("expected failure")
            return
        }
        #expect(error as? ZeError == .Locked)
        #expect(request.bytes.isEmpty)
    }

    @Test func invalidateFailsPendingAndFutureRequests() {
        let reader = FakeReader(data: pattern(slice * 50))
        let loader = EncryptedVideoLoader(reader: reader, mime: nil)
        let first = FakeRequest(range: (0, nil))
        first.onRespond = { [unowned loader] _ in loader.invalidate() }
        loader.handle(first)
        #expect(first.waitUntilFinished())
        let later = FakeRequest(range: (0, nil))
        loader.handle(later)
        #expect(later.waitUntilFinished())
        for request in [first, later] {
            guard case .failure(let error)? = request.result else {
                Issue.record("expected failure")
                continue
            }
            #expect(error as? ZeError == .Locked)
        }
        #expect(reader.readLog.count == 1)
    }
}

@MainActor
struct VideoPlaybackIntegrationTests {
    /// Writes a 1-second H.264 movie of solid-colour frames.
    private static func makeMovie(at url: URL) async throws {
        let size = CGSize(width: 64, height: 64)
        let writer = try AVAssetWriter(outputURL: url, fileType: .mp4)
        let input = AVAssetWriterInput(
            mediaType: .video,
            outputSettings: [
                AVVideoCodecKey: AVVideoCodecType.h264,
                AVVideoWidthKey: Int(size.width), AVVideoHeightKey: Int(size.height),
            ])
        let adaptor = AVAssetWriterInputPixelBufferAdaptor(
            assetWriterInput: input,
            sourcePixelBufferAttributes: [
                kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
                kCVPixelBufferWidthKey as String: Int(size.width),
                kCVPixelBufferHeightKey as String: Int(size.height),
            ])
        writer.add(input)
        guard writer.startWriting() else { throw writer.error ?? CocoaError(.fileWriteUnknown) }
        writer.startSession(atSourceTime: .zero)
        for frame in 0..<10 {
            while !input.isReadyForMoreMediaData { try await Task.sleep(for: .milliseconds(5)) }
            var buffer: CVPixelBuffer?
            CVPixelBufferCreate(
                nil, Int(size.width), Int(size.height), kCVPixelFormatType_32BGRA, nil, &buffer)
            let pixels = try #require(buffer)
            CVPixelBufferLockBaseAddress(pixels, [])
            memset(CVPixelBufferGetBaseAddress(pixels), 0x80, CVPixelBufferGetDataSize(pixels))
            CVPixelBufferUnlockBaseAddress(pixels, [])
            adaptor.append(pixels, withPresentationTime: CMTime(value: Int64(frame), timescale: 10))
        }
        input.markAsFinished()
        await writer.finishWriting()
        if writer.status != .completed { throw writer.error ?? CocoaError(.fileWriteUnknown) }
    }

    @Test func customSchemeAssetLoadsDurationAndIsPlayable() async throws {
        let url = FileManager.default.temporaryDirectory.appending(path: "ze-test-\(UUID().uuidString).mp4")
        defer { try? FileManager.default.removeItem(at: url) }
        try await Self.makeMovie(at: url)
        let movie = try Data(contentsOf: url)

        let loader = EncryptedVideoLoader(reader: FakeReader(data: movie), mime: "video/mp4")
        let asset = AVURLAsset(url: try #require(EncryptedVideoLoader.url(objectID: "00ff")))
        asset.resourceLoader.setDelegate(loader, queue: loader.queue)

        let duration = try await asset.load(.duration).seconds
        #expect(abs(duration - 1) < 0.2)
        #expect(try await asset.load(.isPlayable))
    }
}

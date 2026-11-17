import AVFoundation
import UniformTypeIdentifiers
import ZeroEnclaveCore

/// Random-access plaintext source; implemented by the core's object reader.
protocol RangeReader: AnyObject, Sendable {
    var plaintextLength: UInt64 { get }
    func readRange(offset: UInt64, len: UInt32) throws -> Data
}

extension ObjectReaderHandle: RangeReader {
    var plaintextLength: UInt64 { plaintextLen() }
}

/// The parts of `AVAssetResourceLoadingRequest` the loader needs.
protocol VideoLoadingRequest: AnyObject, Sendable {
    var requestKey: ObjectIdentifier { get }
    var isCancelled: Bool { get }
    var wantsContentInformation: Bool { get }
    /// Requested byte range; `length == nil` means up to the end of the resource.
    var dataRange: (offset: Int64, length: Int64?)? { get }
    func fillContentInformation(contentType: String, length: Int64)
    func respond(with data: Data)
    func finish()
    func finish(with error: Error)
}

final class AVVideoLoadingRequest: VideoLoadingRequest, @unchecked Sendable {
    private let request: AVAssetResourceLoadingRequest

    init(_ request: AVAssetResourceLoadingRequest) { self.request = request }

    var requestKey: ObjectIdentifier { ObjectIdentifier(request) }
    var isCancelled: Bool { request.isCancelled }
    var wantsContentInformation: Bool { request.contentInformationRequest != nil }

    var dataRange: (offset: Int64, length: Int64?)? {
        guard let data = request.dataRequest else { return nil }
        return (data.requestedOffset, data.requestsAllDataToEndOfResource ? nil : Int64(data.requestedLength))
    }

    func fillContentInformation(contentType: String, length: Int64) {
        guard let info = request.contentInformationRequest else { return }
        info.contentType = contentType
        info.contentLength = length
        info.isByteRangeAccessSupported = true
    }

    func respond(with data: Data) { request.dataRequest?.respond(with: data) }
    func finish() { request.finishLoading() }
    func finish(with error: Error) { request.finishLoading(with: error) }
}

/// Serves an encrypted object to AVFoundation by byte range, without any plaintext file.
/// Decrypted bytes are only held for the slice being delivered.
final class EncryptedVideoLoader: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    static let scheme = "zenc"
    static let sliceSize: Int64 = 1 << 20
    static let fallbackContentType = "com.apple.quicktime-movie"

    private struct Job {
        let request: VideoLoadingRequest
        var offset: Int64
        let end: Int64
    }

    let queue = DispatchQueue(label: "zeroenclave.video-loader")
    private let contentType: String
    // All mutable state below is confined to `queue`.
    private var reader: RangeReader?
    private var jobs: [ObjectIdentifier: Job] = [:]

    init(reader: RangeReader, mime: String?) {
        self.reader = reader
        if let mime, let type = UTType(mimeType: mime), type.conforms(to: .audiovisualContent) {
            contentType = type.identifier
        } else {
            contentType = Self.fallbackContentType
        }
    }

    static func url(objectID: String) -> URL? {
        URL(string: "\(scheme)://\(objectID)")
    }

    /// Drops the reader and fails all pending requests.
    func invalidate() {
        queue.async { self.invalidateOnQueue() }
    }

    private func invalidateOnQueue() {
        reader = nil
        let pending = jobs.values.map(\.request)
        jobs = [:]
        for request in pending { request.finish(with: ZeError.Locked) }
    }

    /// Number of requests still being served (for tests).
    var pendingCount: Int { queue.sync { jobs.count } }

    // MARK: AVAssetResourceLoaderDelegate

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
    ) -> Bool {
        guard loadingRequest.request.url?.scheme == Self.scheme else { return false }
        handle(AVVideoLoadingRequest(loadingRequest))
        return true
    }

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader, didCancel loadingRequest: AVAssetResourceLoadingRequest
    ) {
        let key = ObjectIdentifier(loadingRequest)
        queue.async { self.jobs[key] = nil }
    }

    // MARK: Serving

    func handle(_ request: VideoLoadingRequest) {
        queue.async { self.start(request) }
    }

    private func start(_ request: VideoLoadingRequest) {
        guard let reader else {
            request.finish(with: ZeError.Locked)
            return
        }
        let total = Int64(clamping: reader.plaintextLength)
        if request.wantsContentInformation {
            request.fillContentInformation(contentType: contentType, length: total)
        }
        guard let range = request.dataRange else {
            request.finish()
            return
        }
        let offset = max(range.offset, 0)
        let end = range.length.map { min(offset &+ max($0, 0), total) } ?? total
        guard offset < end else {
            request.finish()
            return
        }
        jobs[request.requestKey] = Job(request: request, offset: offset, end: end)
        serveNextSlice(request.requestKey)
    }

    /// Delivers one slice and re-enqueues itself, so other requests and cancellations interleave.
    private func serveNextSlice(_ key: ObjectIdentifier) {
        guard var job = jobs[key] else { return }
        if job.request.isCancelled {
            jobs[key] = nil
            return
        }
        guard let reader else {
            jobs[key] = nil
            job.request.finish(with: ZeError.Locked)
            return
        }
        let length = UInt32(min(Self.sliceSize, job.end - job.offset))
        do {
            let data = try reader.readRange(offset: UInt64(job.offset), len: length)
            guard !data.isEmpty else { throw ZeError.OutOfRange }
            job.request.respond(with: data)
            job.offset += Int64(data.count)
        } catch {
            jobs[key] = nil
            job.request.finish(with: error)
            return
        }
        if job.offset >= job.end {
            jobs[key] = nil
            job.request.finish()
            return
        }
        jobs[key] = job
        queue.async { self.serveNextSlice(key) }
    }
}

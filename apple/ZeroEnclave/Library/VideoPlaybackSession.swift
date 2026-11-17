import AVFoundation

/// One playback of an encrypted video: asset, loader and player. `stop()` releases all of them.
@MainActor
final class VideoPlaybackSession {
    private(set) var player: AVPlayer?
    private var loader: EncryptedVideoLoader?
    private var timeObserver: Any?
    private var audioActive = false
    private let onProgress: () -> Void
    private let onStop: () -> Void

    init?(
        objectID: String, reader: RangeReader, mime: String?,
        onProgress: @escaping () -> Void, onStop: @escaping () -> Void
    ) {
        guard let url = EncryptedVideoLoader.url(objectID: objectID) else { return nil }
        let loader = EncryptedVideoLoader(reader: reader, mime: mime)
        let asset = AVURLAsset(url: url)
        asset.resourceLoader.setDelegate(loader, queue: loader.queue)
        let player = AVPlayer(playerItem: AVPlayerItem(asset: asset))
        player.allowsExternalPlayback = false
        self.loader = loader
        self.player = player
        self.onProgress = onProgress
        self.onStop = onStop
        // Playback keeps the vault open: progress resets the inactivity timer.
        timeObserver = player.addPeriodicTimeObserver(
            forInterval: CMTime(seconds: 1, preferredTimescale: 1), queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.reportProgress() }
        }
    }

    private func reportProgress() {
        if player?.timeControlStatus == .playing { onProgress() }
    }

    func play() {
        activateAudioSession()
        player?.play()
    }

    /// Plays sound even with the silent switch on.
    private func activateAudioSession() {
        let session = AVAudioSession.sharedInstance()
        try? session.setCategory(.playback, mode: .moviePlayback)
        audioActive = (try? session.setActive(true)) != nil
    }

    func stop() {
        guard let player else { return }
        player.pause()
        if let timeObserver { player.removeTimeObserver(timeObserver) }
        timeObserver = nil
        player.replaceCurrentItem(with: nil)
        loader?.invalidate()
        loader = nil
        self.player = nil
        if audioActive {
            audioActive = false
            try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        }
        onStop()
    }
}

import Foundation
import Observation
import UIKit
import ZeroEnclaveCore

struct LibraryItem: Identifiable, Hashable, Sendable {
    let id: String
    let kind: ItemKind
    let meta: ItemMeta
    let originalID: String?
    let smallID: String?
    let largeID: String?
    let albumIDs: Set<String>
    /// In an album that is not shown in All Photos.
    let hiddenInAll: Bool
    /// When the item was moved to the trash; nil if it is not trashed.
    let trashedAt: Date?

    init(_ summary: ItemSummary) {
        id = summary.id
        kind = summary.kind
        meta = summary.meta
        func object(_ role: ObjectRole) -> String? {
            summary.objects.first { $0.role == role }?.objectId
        }
        originalID = object(.original)
        smallID = object(.thumbSmall)
        largeID = object(.thumbLarge)
        albumIDs = Set(summary.albums)
        hiddenInAll = summary.hiddenInAll
        trashedAt = summary.trashedAt.map { Date(timeIntervalSince1970: Double($0) / 1000) }
    }

    /// Whole days left before the trash deletes the item for good; 0 on the last day.
    func daysLeftInTrash(now: Date = .now) -> Int? {
        guard let trashedAt else { return nil }
        let left = trashedAt.addingTimeInterval(TrashPolicy.retention).timeIntervalSince(now)
        return max(0, Int((left / 86_400).rounded(.up)))
    }

    var isVideo: Bool { kind == .video }

    /// Capture date, or the import date when the file carries none.
    var date: Date {
        Date(timeIntervalSince1970: Double(meta.created ?? meta.imported) / 1000)
    }

    var durationSeconds: Int? { meta.duration.map { Int(($0 + 500) / 1000) } }
}

enum TrashPolicy {
    /// Mirrors `TRASH_RETENTION_MS` of the core (30 days).
    static let retention: TimeInterval = 30 * 24 * 60 * 60
}

struct LibraryAlbum: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let itemCount: Int
    /// Newest member, shown as the album thumbnail.
    let coverID: String?
    /// A view-lock code is set.
    let locked: Bool
    let showInAll: Bool

    init(_ summary: AlbumSummary) {
        id = summary.id
        name = summary.name
        itemCount = Int(summary.itemCount)
        coverID = summary.coverItem
        locked = summary.locked
        showInAll = summary.showInAll
    }
}

enum AlbumName {
    static let maxLength = 100

    /// The trimmed name, or nil if it is empty or too long.
    static func validated(_ raw: String) -> String? {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return (1...maxLength).contains(name.count) ? name : nil
    }
}

/// Reads the library of the unlocked vault and decrypts images into the session cache.
@MainActor
@Observable
final class LibraryStore {
    private(set) var items: [LibraryItem] = []
    private(set) var albums: [LibraryAlbum] = []

    /// Unlock state of locked albums; reset together with the store on every vault unlock.
    let albumLock = AlbumLock()

    @ObservationIgnored private let vault: VaultService

    init(vault: VaultService) {
        self.vault = vault
    }

    private var handle: VaultHandle? {
        if case .unlocked(let handle) = vault.state { return handle }
        return nil
    }

    func reload() async {
        guard let handle else { return }
        let loaded = await Task.detached(priority: .userInitiated) { () -> ([ItemSummary], [AlbumSummary])? in
            if let items = try? handle.items(), let albums = try? handle.albums() {
                return (items, albums)
            }
            return nil
        }.value
        guard let loaded, vault.isUnlocked else { return }
        items = loaded.0.map(LibraryItem.init).sorted { $0.date > $1.date }
        albums = loaded.1.map(LibraryAlbum.init)
    }

    /// Members of an album; trashed items are left out.
    func items(in albumID: String) -> [LibraryItem] {
        items.filter { $0.trashedAt == nil && $0.albumIDs.contains(albumID) }
    }

    /// The All Photos list: items in an album that is not shown there and trashed items are left out.
    var photos: [LibraryItem] {
        items.filter { !$0.hiddenInAll && $0.trashedAt == nil }
    }

    /// Recently Deleted, newest first.
    var trashed: [LibraryItem] {
        items.filter { $0.trashedAt != nil }
            .sorted { ($0.trashedAt ?? .distantPast) > ($1.trashedAt ?? .distantPast) }
    }

    // MARK: Albums

    /// Returns the new album id, or nil if the name or code is invalid or the vault refused.
    /// With a `code` the album is created locked.
    func createAlbum(named raw: String, code: String? = nil) async -> String? {
        guard let handle, let name = AlbumName.validated(raw) else { return nil }
        if let code, !AlbumCode.isValid(code) { return nil }
        let id = await Task.detached(priority: .userInitiated) { () -> String? in
            guard let id = try? handle.createAlbum(name: name) else { return nil }
            if let code {
                do {
                    try handle.setAlbumPin(albumId: id, code: code)
                } catch {
                    try? handle.deleteAlbum(albumId: id)
                    return nil
                }
            }
            return id
        }.value
        await reload()
        return id
    }

    func setShowInAll(id: String, _ show: Bool) async -> Bool {
        guard let handle else { return false }
        return await mutate { try handle.setAlbumShowInAll(albumId: id, show: show) }
    }

    /// Locks the album with `code`, or removes the lock with nil. A freshly set code keeps
    /// the album open until it is left.
    func setAlbumCode(id: String, _ code: String?) async -> Bool {
        guard let handle else { return false }
        if let code, !AlbumCode.isValid(code) { return false }
        let ok = await mutate { try handle.setAlbumPin(albumId: id, code: code) }
        if ok {
            if code == nil { albumLock.forget(id) } else { albumLock.grant(id) }
        }
        return ok
    }

    /// Checks the code of a locked album and opens it on success. After five wrong codes the
    /// album stays blocked until the vault is unlocked again.
    func unlockAlbum(id: String, code: String) async -> AlbumUnlockResult {
        guard let handle, !albumLock.isBlocked(id) else { return .blocked }
        let valid = await Task.detached(priority: .userInitiated) {
            (try? handle.verifyAlbumPin(albumId: id, code: code)) ?? false
        }.value
        guard vault.isUnlocked else { return .blocked }
        if valid {
            albumLock.grant(id)
            return .opened
        }
        return albumLock.recordFailure(id)
    }

    /// True if `password` is the master password (not the duress password).
    func verifyMasterPassword(_ password: String) async -> Bool {
        await vault.verifyPassword(password)
    }

    func renameAlbum(id: String, to raw: String) async -> Bool {
        guard let handle, let name = AlbumName.validated(raw) else { return false }
        return await mutate { try handle.renameAlbum(albumId: id, name: name) }
    }

    /// Deletes only the album; its photos stay in the library.
    func deleteAlbum(id: String) async -> Bool {
        guard let handle else { return false }
        let ok = await mutate { try handle.deleteAlbum(albumId: id) }
        if ok { albumLock.forget(id) }
        return ok
    }

    func add(ids: Set<String>, to albumID: String) async -> Bool {
        guard let handle, !ids.isEmpty else { return false }
        let list = Array(ids)
        return await mutate { try handle.addToAlbum(albumId: albumID, itemIds: list) }
    }

    func remove(ids: Set<String>, from albumID: String) async -> Bool {
        guard let handle, !ids.isEmpty else { return false }
        let list = Array(ids)
        return await mutate { try handle.removeFromAlbum(albumId: albumID, itemIds: list) }
    }

    private func mutate(_ work: @escaping @Sendable () throws -> Void) async -> Bool {
        let ok = await Task.detached(priority: .userInitiated) { (try? work()) != nil }.value
        await reload()
        return ok
    }

    func thumbnail(for item: LibraryItem, large: Bool) async -> UIImage? {
        guard let id = large ? item.largeID : item.smallID else { return nil }
        let side = large ? ThumbnailGenerator.largeSide : ThumbnailGenerator.smallSide
        return await image(objectID: id, maxPixel: side)
    }

    /// The decoded original, downsampled to `maxPixel`.
    func original(for item: LibraryItem, maxPixel: Int) async -> UIImage? {
        guard let id = item.originalID, !item.isVideo else { return nil }
        return await image(objectID: id, maxPixel: maxPixel)
    }

    /// The decrypted original file; nil when the vault is locked or the object is unreadable.
    func originalData(for item: LibraryItem) async -> Data? {
        guard let id = item.originalID, let handle else { return nil }
        let data = await Task.detached(priority: .userInitiated) {
            try? handle.openObject(objectId: id).readAll()
        }.value
        return vault.isUnlocked ? data : nil
    }

    /// Opens a streaming playback session for a video; nil when the vault is locked or unreadable.
    func playbackSession(for item: LibraryItem) async -> VideoPlaybackSession? {
        guard item.isVideo, let id = item.originalID, let handle else { return nil }
        let reader = await Task.detached(priority: .userInitiated) {
            try? handle.openObject(objectId: id)
        }.value
        guard let reader, vault.isUnlocked else { return nil }
        // The stop closure is set after init; the session reference is weak to avoid a cycle.
        let box = TokenBox()
        let vault = vault
        let session = VideoPlaybackSession(
            objectID: id, reader: reader, mime: item.meta.mime,
            onProgress: { vault.noteActivity() },
            onStop: { [box] in
                if let token = box.token { vault.unregisterPlayback(token) }
            })
        guard let session else { return nil }
        box.token = vault.registerPlayback { [weak session] in session?.stop() }
        return session
    }

    /// Moves items to Recently Deleted. Returns false when the vault refused it.
    func trash(ids: Set<String>, now: Date = .now) async -> Bool {
        guard let handle, !ids.isEmpty else { return false }
        let list = Array(ids)
        let ms = Self.milliseconds(now)
        return await mutate { try handle.trashItems(ids: list, nowMs: ms) }
    }

    /// Takes items out of Recently Deleted; premium, the caller goes through the gate.
    func restore(ids: Set<String>) async -> Bool {
        guard let handle, !ids.isEmpty else { return false }
        let list = Array(ids)
        return await mutate { try handle.restoreItems(ids: list) }
    }

    /// Deletes items for good. Returns false when the vault refused the deletion.
    func deletePermanently(ids: Set<String>) async -> Bool {
        guard let handle, !ids.isEmpty else { return false }
        let list = Array(ids)
        return await mutate { try handle.deleteItems(ids: list) }
    }

    /// Deletes everything in Recently Deleted for good.
    func emptyTrash() async -> Bool {
        await deletePermanently(ids: Set(trashed.map(\.id)))
    }

    /// Deletes trashed items older than the retention period; returns how many were removed.
    @discardableResult
    func purgeExpired(now: Date = .now) async -> Int {
        guard let handle else { return 0 }
        let ms = Self.milliseconds(now)
        let count = await Task.detached(priority: .userInitiated) {
            (try? handle.purgeExpired(nowMs: ms)) ?? 0
        }.value
        await reload()
        return Int(count)
    }

    private static func milliseconds(_ date: Date) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970 * 1000))
    }

    private func image(objectID: String, maxPixel: Int) async -> UIImage? {
        let key = "\(objectID)@\(maxPixel)"
        let cache = vault.imageCache
        if let hit = cache.image(forKey: key) { return hit }
        guard let handle else { return nil }
        let image = await Task.detached(priority: .userInitiated) { () -> UIImage? in
            guard let data = try? handle.openObject(objectId: objectID).readAll() else { return nil }
            return ImageDecoder.downsample(data, maxPixel: maxPixel)
        }.value
        // A lock during the read must not leave plaintext behind in the cache.
        guard let image, vault.isUnlocked else { return nil }
        cache.insert(image, forKey: key)
        return image
    }
}

private final class TokenBox {
    var token: UUID?
}

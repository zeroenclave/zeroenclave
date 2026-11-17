import ImageIO
import Testing
import UIKit
import UniformTypeIdentifiers
import ZeroEnclaveCore

@testable import ZeroEnclave

/// Reads a local file instead of a PHPicker result.
private struct FileSource: ImportSource {
    let url: URL
    var suggestedName: String? { "synthetic" }
    var assetIdentifier: String? { nil }

    func withFile<T: Sendable>(
        _ body: @escaping @Sendable (URL, UTType) async throws -> T
    ) async throws -> T {
        try await body(url, .jpeg)
    }
}

@MainActor
struct AlbumTests {
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

    private func jpegFile() throws -> URL {
        let context = CGContext(
            data: nil, width: 32, height: 32, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        context.setFillColor(UIColor.systemTeal.cgColor)
        context.fill(CGRect(x: 0, y: 0, width: 32, height: 32))
        let data = NSMutableData()
        let destination = CGImageDestinationCreateWithData(
            data, UTType.jpeg.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(destination, context.makeImage()!, nil)
        CGImageDestinationFinalize(destination)
        let url = FileManager.default.temporaryDirectory.appending(path: "ze-test-\(UUID().uuidString).jpg")
        try (data as Data).write(to: url)
        return url
    }

    /// Imports `count` synthetic photos and returns a loaded store.
    private func storeWithItems(_ count: Int, service: VaultService) async throws -> LibraryStore {
        guard case .unlocked(let handle) = service.state else { throw ThumbnailError.unreadable }
        let url = try jpegFile()
        defer { try? FileManager.default.removeItem(at: url) }
        for _ in 0..<count {
            _ = try await ImportPipeline(handle: handle).importItem(FileSource(url: url))
        }
        let store = LibraryStore(vault: service)
        await store.reload()
        return store
    }

    @Test func nameValidation() {
        #expect(AlbumName.validated("  Trip ") == "Trip")
        #expect(AlbumName.validated("   ") == nil)
        #expect(AlbumName.validated(String(repeating: "a", count: 100)) != nil)
        #expect(AlbumName.validated(String(repeating: "a", count: 101)) == nil)
    }

    @Test func createRenameDeleteAlbum() async throws {
        let service = await unlockedService()
        let store = try await storeWithItems(2, service: service)
        #expect(await store.createAlbum(named: "   ") == nil)
        let id = try #require(await store.createAlbum(named: " Trip "))
        #expect(store.albums.map(\.name) == ["Trip"])
        #expect(store.albums.first?.itemCount == 0)

        #expect(await store.renameAlbum(id: id, to: "Berge"))
        #expect(store.albums.first?.name == "Berge")
        #expect(await !store.renameAlbum(id: id, to: ""))

        #expect(await store.deleteAlbum(id: id))
        #expect(store.albums.isEmpty)
        // Deleting an album keeps the photos.
        #expect(store.items.count == 2)
        #expect(await !store.deleteAlbum(id: id))
    }

    @Test func addAndRemoveItems() async throws {
        let service = await unlockedService()
        let store = try await storeWithItems(3, service: service)
        let id = try #require(await store.createAlbum(named: "A"))
        let other = try #require(await store.createAlbum(named: "B"))
        let ids = store.items.map(\.id)

        #expect(await store.add(ids: [ids[0], ids[1]], to: id))
        #expect(await store.add(ids: [ids[1]], to: other))
        #expect(Set(store.items(in: id).map(\.id)) == [ids[0], ids[1]])
        #expect(store.albums.first { $0.id == id }?.itemCount == 2)
        #expect(store.albums.first { $0.id == id }?.coverID != nil)
        // An item can be in several albums.
        #expect(store.items.first { $0.id == ids[1] }?.albumIDs == [id, other])
        // "All Photos" is unaffected.
        #expect(store.items.count == 3)

        #expect(await store.remove(ids: [ids[0]], from: id))
        #expect(store.items(in: id).map(\.id) == [ids[1]])
        #expect(store.items.count == 3)

        // Deleting a photo removes it from all albums.
        #expect(await store.deletePermanently(ids: [ids[1]]))
        #expect(store.items(in: id).isEmpty)
        #expect(store.items(in: other).isEmpty)
        #expect(await !store.add(ids: [], to: id))
        #expect(await !store.add(ids: [ids[1]], to: id))
    }

    @Test func trashHidesItemsAndRestoreBringsThemBack() async throws {
        let service = await unlockedService()
        let store = try await storeWithItems(3, service: service)
        let id = try #require(await store.createAlbum(named: "A"))
        let ids = store.items.map(\.id)
        #expect(await store.add(ids: Set(ids), to: id))

        #expect(await !store.trash(ids: []))
        #expect(await store.trash(ids: [ids[0], ids[1]]))
        #expect(store.photos.map(\.id) == [ids[2]])
        #expect(store.items(in: id).map(\.id) == [ids[2]])
        #expect(store.albums.first?.itemCount == 1)
        #expect(Set(store.trashed.map(\.id)) == [ids[0], ids[1]])
        #expect(store.trashed.allSatisfy { $0.trashedAt != nil && $0.daysLeftInTrash() == 30 })

        // Restore brings items back into All Photos and their album.
        #expect(await store.restore(ids: [ids[0]]))
        #expect(Set(store.photos.map(\.id)) == [ids[0], ids[2]])
        #expect(Set(store.items(in: id).map(\.id)) == [ids[0], ids[2]])
        #expect(store.trashed.map(\.id) == [ids[1]])

        // Permanent delete and empty.
        #expect(await store.deletePermanently(ids: [ids[1]]))
        #expect(store.trashed.isEmpty && store.items.count == 2)
        #expect(await store.trash(ids: [ids[2]]))
        #expect(await store.emptyTrash())
        #expect(store.items.map(\.id) == [ids[0]])
    }

    @Test func purgeExpiredRemovesOnlyExpiredItems() async throws {
        let service = await unlockedService()
        let store = try await storeWithItems(3, service: service)
        let ids = store.items.map(\.id)
        let old = Date.now.addingTimeInterval(-TrashPolicy.retention)
        let recent = Date.now.addingTimeInterval(-TrashPolicy.retention + 3600)
        #expect(await store.trash(ids: [ids[0]], now: old))
        #expect(await store.trash(ids: [ids[1]], now: recent))
        #expect(store.trashed.first { $0.id == ids[1] }?.daysLeftInTrash() == 1)

        #expect(await store.purgeExpired() == 1)
        #expect(Set(store.items.map(\.id)) == [ids[1], ids[2]])
        #expect(store.trashed.map(\.id) == [ids[1]])
        #expect(await store.purgeExpired() == 0)
    }

    @Test func importIntoAlbumAddsItems() async throws {
        let service = await unlockedService()
        let store = LibraryStore(vault: service)
        let id = try #require(await store.createAlbum(named: "Import"))
        let url = try jpegFile()
        defer { try? FileManager.default.removeItem(at: url) }
        let importer = ImportCoordinator(vault: service, store: store)
        importer.start([FileSource(url: url), FileSource(url: url)], albumID: id)
        while importer.isRunning { try await Task.sleep(for: .milliseconds(20)) }
        #expect(importer.summary?.imported == 2)
        #expect(store.items.count == 2)
        #expect(store.items(in: id).count == 2)
    }

    @Test func importWithoutReportSkipsSummaryOnSuccess() async throws {
        let service = await unlockedService()
        let store = LibraryStore(vault: service)
        let url = try jpegFile()
        defer { try? FileManager.default.removeItem(at: url) }
        let importer = ImportCoordinator(vault: service, store: store)
        importer.start([FileSource(url: url)], reportSuccess: false)
        while importer.isRunning { try await Task.sleep(for: .milliseconds(20)) }
        #expect(importer.summary == nil)
        #expect(store.items.count == 1)
    }

    @Test func createOpenAndLockedAlbums() async throws {
        let service = await unlockedService()
        let store = LibraryStore(vault: service)
        let open = try #require(await store.createAlbum(named: "Open"))
        let locked = try #require(await store.createAlbum(named: "Locked", code: "1234"))
        #expect(await store.createAlbum(named: "Bad", code: "12") == nil)
        #expect(await store.createAlbum(named: "Bad", code: "12ab") == nil)
        // A refused code leaves no album behind.
        #expect(store.albums.count == 2)

        let openAlbum = try #require(store.albums.first { $0.id == open })
        let lockedAlbum = try #require(store.albums.first { $0.id == locked })
        #expect(!openAlbum.locked && openAlbum.showInAll)
        #expect(lockedAlbum.locked && !lockedAlbum.showInAll)
    }

    @Test func allPhotosHidesItemsOfHiddenAlbums() async throws {
        let service = await unlockedService()
        let store = try await storeWithItems(3, service: service)
        let ids = store.items.map(\.id)
        let open = try #require(await store.createAlbum(named: "Open"))
        let locked = try #require(await store.createAlbum(named: "Locked", code: "1234"))
        #expect(await store.add(ids: [ids[0], ids[1]], to: open))
        #expect(await store.add(ids: [ids[1], ids[2]], to: locked))

        // Item 1 is in a shown and a hidden album: hidden. Hidden items stay in their albums.
        #expect(store.photos.map(\.id) == [ids[0]])
        #expect(store.items.count == 3)
        #expect(Set(store.items(in: locked).map(\.id)) == [ids[1], ids[2]])

        #expect(await store.setShowInAll(id: locked, true))
        #expect(Set(store.photos.map(\.id)) == Set(ids))
        #expect(await store.setShowInAll(id: open, false))
        #expect(await store.setShowInAll(id: locked, false))
        #expect(store.photos.isEmpty)

        // Deleting the albums brings the items back.
        #expect(await store.deleteAlbum(id: open))
        #expect(await store.deleteAlbum(id: locked))
        #expect(Set(store.photos.map(\.id)) == Set(ids))
    }

    @Test func codeEntryOpensAndCounts() async throws {
        let service = await unlockedService()
        let store = LibraryStore(vault: service)
        let id = try #require(await store.createAlbum(named: "Locked", code: "4321"))
        #expect(!store.albumLock.isOpen(id))

        #expect(await store.unlockAlbum(id: id, code: "0000") == .wrong(remaining: 4))
        #expect(await store.unlockAlbum(id: id, code: "12") == .wrong(remaining: 3))
        #expect(!store.albumLock.isOpen(id))
        #expect(await store.unlockAlbum(id: id, code: "4321") == .opened)
        #expect(store.albumLock.isOpen(id))

        // Leaving the album closes it again.
        store.albumLock.close(id)
        #expect(!store.albumLock.isOpen(id))
    }

    @Test func fiveWrongCodesBlockUntilNextUnlock() async throws {
        let service = await unlockedService()
        let store = LibraryStore(vault: service)
        let id = try #require(await store.createAlbum(named: "Locked", code: "4321"))
        for remaining in (0..<4).reversed() {
            #expect(await store.unlockAlbum(id: id, code: "1111") == .wrong(remaining: remaining + 1))
        }
        #expect(await store.unlockAlbum(id: id, code: "1111") == .blocked)
        // Even the right code is refused now.
        #expect(await store.unlockAlbum(id: id, code: "4321") == .blocked)
        #expect(!store.albumLock.isOpen(id))

        // A new unlock builds a new store and starts with a clean counter.
        let fresh = LibraryStore(vault: service)
        await fresh.reload()
        #expect(await fresh.unlockAlbum(id: id, code: "4321") == .opened)
    }

    @Test func masterPasswordOverridesCode() async throws {
        let service = await unlockedService()
        let store = LibraryStore(vault: service)
        let id = try #require(await store.createAlbum(named: "Locked", code: "4321"))
        for _ in 0..<5 { _ = await store.unlockAlbum(id: id, code: "0000") }
        #expect(store.albumLock.isBlocked(id))

        #expect(await !store.verifyMasterPassword("wrong passphrase"))
        #expect(await store.verifyMasterPassword("synthetic test passphrase"))
        #expect(await store.setAlbumCode(id: id, nil))
        let album = try #require(store.albums.first { $0.id == id })
        #expect(!album.locked)
        #expect(!store.albumLock.isBlocked(id))

        // Setting a new code afterwards locks again and keeps the album open.
        #expect(await store.setAlbumCode(id: id, "9876"))
        #expect(store.albums.first { $0.id == id }?.locked == true)
        #expect(store.albumLock.isOpen(id))
        #expect(await !store.setAlbumCode(id: id, "98"))
    }

    @Test func codeRules() {
        #expect(AlbumCode.isValid("0123"))
        #expect(!AlbumCode.isValid("123"))
        #expect(!AlbumCode.isValid("12345"))
        #expect(!AlbumCode.isValid("12a4"))
        #expect(AlbumCode.sanitized("1a2b3c4d5") == "1234")
        #expect(AlbumCode.matches("1234", "1234"))
        #expect(!AlbumCode.matches("1234", "1235"))
    }

    @Test func albumsAreGatedByPremium() {
        let entitlements = Entitlements(defaults: defaults, trialStore: MemoryTrialStore(), extraSources: [])
        let gate = PremiumGate()
        var ran = false
        #expect(!gate.perform(.albums, entitlements: entitlements) { ran = true })
        #expect(gate.isPresentingRequired && !ran)
        gate.isPresentingRequired = false
        entitlements.activatePreRelease()
        #expect(gate.perform(.albums, entitlements: entitlements) { ran = true })
        #expect(!gate.isPresentingRequired && ran)
    }
}

import Foundation
import UIKit
import Testing
import ZeroEnclaveCore

@testable import ZeroEnclave

@MainActor
struct SettingsTests {
    private static let password = "synthetic test passphrase"

    private let defaults = UserDefaults(suiteName: "ze-test-\(UUID().uuidString)")!

    private func makeRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appending(path: "ze-test-\(UUID().uuidString)", directoryHint: .isDirectory)
            .appending(path: "Vault", directoryHint: .isDirectory)
    }

    private func makeService(root: URL) -> VaultService {
        VaultService(root: root, defaults: defaults, calibrate: { kdfDefault() })
    }

    private func unlockedService(root: URL) async -> VaultService {
        let service = makeService(root: root)
        service.beginOnboarding()
        _ = await service.createVault(password: Self.password)
        service.acknowledgeRecoveryKey()
        service.finishOnboarding()
        return service
    }

    private func handle(of service: VaultService) throws -> VaultHandle {
        guard case .unlocked(let handle) = service.state else {
            throw CocoaError(.fileReadUnknown)
        }
        return handle
    }

    private func addItem(_ bytes: Data, to handle: VaultHandle) throws {
        let session = try handle.beginImport(
            kind: .photo, meta: ItemMeta(filename: "a.jpg", created: nil, imported: 1, mime: "image/jpeg",
                width: 1, height: 1, duration: nil, size: UInt64(bytes.count)))
        let writer = try session.addObject(role: .original)
        try writer.write(data: bytes)
        try writer.finish()
        _ = try session.commit()
    }

    private func originalBytes(of handle: VaultHandle) throws -> [Data] {
        try handle.items().compactMap { item in
            guard let object = item.objects.first(where: { $0.role == .original }) else { return nil }
            return try handle.openObject(objectId: object.objectId).readAll()
        }
    }

    @Test func changePasswordReplacesOldPassword() async throws {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        let new = "another synthetic passphrase"

        #expect(await service.changePassword(old: "wrong password", new: new) != nil)
        #expect(await service.changePassword(old: Self.password, new: new) == nil)

        guard case .wrongPassword = try vaultUnlock(root: root.path, password: Self.password, bootTime: 1, now: 2) else {
            Issue.record("old password still works")
            return
        }
        guard case .open = try vaultUnlock(root: root.path, password: new, bootTime: 1, now: 2) else {
            Issue.record("new password does not work")
            return
        }
    }

    @Test func duressMustDifferFromMasterPassword() async {
        let service = await unlockedService(root: makeRoot())
        #expect(await service.setDuress(masterPassword: Self.password, duress: Self.password) != nil)
        #expect(await service.setDuress(masterPassword: Self.password, duress: "different duress phrase") == nil)
        #expect(await service.disableDuress(masterPassword: Self.password) == nil)
    }

    @Test func rotateRecoveryKeyReturnsNewKey() async throws {
        let service = await unlockedService(root: makeRoot())
        #expect((try? await service.rotateRecoveryKey(password: "wrong password").get()) == nil)
        let key = try #require(try? await service.rotateRecoveryKey(password: Self.password).get())
        #expect(key.split(separator: "-").count == 14)
    }

    @Test func exportFromCopyMergesIntoOriginal() async throws {
        let rootA = makeRoot()
        let a = await unlockedService(root: rootA)
        a.lock()
        // A second copy of the same vault gets an item that the first one lacks.
        let rootB = makeRoot()
        try FileManager.default.createDirectory(
            at: rootB.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: rootA, to: rootB)
        let b = makeService(root: rootB)
        #expect(await b.unlock(password: Self.password) == .unlocked)
        let bytes = Data("synthetic image bytes".utf8)
        try addItem(bytes, to: try handle(of: b))

        let dir = try TemporaryFiles.makeDirectory()
        defer { TemporaryFiles.remove(dir.appending(path: "x")) }
        let file = dir.appending(path: BackupName.defaultName() + ".zenx")
        #expect(await b.exportBackup(to: file) { _, _ in } == nil)
        #expect(FileManager.default.fileExists(atPath: file.path))

        #expect(await a.unlock(password: Self.password) == .unlocked)
        let handle = try handle(of: a)
        #expect(try handle.items().isEmpty)

        let wrong = await a.importBackup(from: file, secret: .password(password: "nope"))
        #expect((try? wrong.get()) == nil)

        let result = try await a.importBackup(from: file, secret: .password(password: Self.password)).get()
        guard case .merged(let objects, _) = result else {
            Issue.record("expected merge")
            return
        }
        #expect(objects > 0)
        #expect(try originalBytes(of: handle) == [bytes])
    }

    @Test func restoreIntoFreshInstallThenUnlock() async throws {
        let source = await unlockedService(root: makeRoot())
        let bytes = Data("synthetic image bytes".utf8)
        try addItem(bytes, to: try handle(of: source))
        let dir = try TemporaryFiles.makeDirectory()
        defer { TemporaryFiles.remove(dir.appending(path: "x")) }
        let file = dir.appending(path: "backup.zenx")
        #expect(await source.exportBackup(to: file) { _, _ in } == nil)

        let fresh = makeService(root: makeRoot())
        #expect(await fresh.restoreBackup(from: file, secret: .password(password: "nope")) != nil)
        #expect(await fresh.restoreBackup(from: file, secret: .password(password: Self.password)) == nil)
        guard case .locked = fresh.state else {
            Issue.record("expected locked")
            return
        }
        #expect(await fresh.unlock(password: Self.password) == .unlocked)
        #expect(try originalBytes(of: try handle(of: fresh)) == [bytes])
    }

    @Test func inactivityTimeoutIsPersisted() {
        let service = makeService(root: makeRoot())
        #expect(service.inactivityMinutes == 5)
        service.setInactivityMinutes(15)
        service.setInactivityMinutes(7)
        #expect(service.inactivityMinutes == 15)
        #expect(makeService(root: makeRoot()).inactivityMinutes == 15)
    }

    @Test func backupNameUsesIsoDate() {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        #expect(BackupName.defaultName(date: date).hasPrefix("ZeroEnclave-Backup-20"))
    }
}

@MainActor
struct PrivacyWindowTests {
    @Test func coverIsShownAboveAlertsAndHidden() {
        let controller = PrivacyWindowController(needsCover: { true })
        #expect(!controller.isVisible)
        controller.show(in: nil)
        #expect(controller.isVisible)
        #expect(controller.window?.windowLevel ?? .normal > .alert)
        controller.hide()
        #expect(!controller.isVisible)
    }

    @Test func preparedWindowIsHiddenWithLoadedView() {
        let controller = PrivacyWindowController(needsCover: { true })
        controller.prepare(in: nil)
        #expect(!controller.isVisible)
        #expect(controller.window?.rootViewController?.isViewLoaded == true)
        controller.show(in: nil)
        controller.show(in: nil)
        #expect(controller.isVisible)
    }

    @Test func appDelegateAttachesSceneDelegate() {
        let configuration = AppDelegate.sceneConfiguration(role: .windowApplication)
        #expect(configuration.delegateClass == SceneDelegate.self)
    }

    @Test func appIconChoicesMatchBundle() {
        let icons = Bundle.main.object(forInfoDictionaryKey: "CFBundleIcons") as? [String: Any]
        let alternates = icons?["CFBundleAlternateIcons"] as? [String: Any] ?? [:]
        for choice in AppIconChoice.allCases {
            #expect(UIImage(named: choice.logoName) != nil)
            #expect(UIImage(named: choice.markName) != nil)
            if let name = choice.alternateName { #expect(alternates[name] != nil) }
        }
        #expect(AppIconChoice.allCases.filter { !$0.isPremium } == [.standard])
    }

    @Test func coverFollowsSystemAppearance() {
        let controller = PrivacyWindowController(needsCover: { true })
        controller.prepare(in: nil)
        #expect(controller.window?.overrideUserInterfaceStyle == .unspecified)
        let background = controller.window?.rootViewController?.view.backgroundColor
        let light = background?.resolvedColor(with: UITraitCollection(userInterfaceStyle: .light))
        let dark = background?.resolvedColor(with: UITraitCollection(userInterfaceStyle: .dark))
        #expect(light != dark)
    }

    @Test func coverShowsMark() {
        let controller = PrivacyViewController()
        controller.loadViewIfNeeded()
        #expect(controller.logoView.image == UIImage(named: AppIconChoice.current.markName))
        #expect(controller.view.backgroundColor != nil)
    }
}

struct SnapshotCleanerTests {
    @Test func removesSnapshotDirectory() throws {
        let library = FileManager.default.temporaryDirectory
            .appending(path: "ze-test-\(UUID().uuidString)", directoryHint: .isDirectory)
        let snapshots = library.appending(path: "SplashBoard/Snapshots/group", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: snapshots, withIntermediateDirectories: true)
        try Data([1]).write(to: snapshots.appending(path: "a.ktx"))
        SnapshotCleaner.removeSnapshots(in: library)
        #expect(!FileManager.default.fileExists(atPath: library.appending(path: "SplashBoard/Snapshots").path))
        SnapshotCleaner.removeSnapshots(in: library)
    }
}

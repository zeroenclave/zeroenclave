import Foundation
import Testing
import ZeroEnclaveCore

@testable import ZeroEnclave

@MainActor
struct VaultServiceTests {
    private static let password = "synthetic test passphrase"

    private let defaults = UserDefaults(suiteName: "ze-test-\(UUID().uuidString)")!

    private func makeRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appending(path: "ze-test-\(UUID().uuidString)", directoryHint: .isDirectory)
            .appending(path: "Vault", directoryHint: .isDirectory)
    }

    private func makeService(
        root: URL, timeout: Duration = VaultService.defaultInactivityTimeout
    ) -> VaultService {
        VaultService(
            root: root, defaults: defaults, inactivityTimeout: timeout, calibrate: { kdfDefault() })
    }

    /// Runs onboarding to completion and returns the recovery key.
    @discardableResult
    private func onboard(_ service: VaultService) async -> String {
        service.beginOnboarding()
        let error = await service.createVault(password: Self.password)
        #expect(error == nil)
        let key = service.pendingRecoveryKey ?? ""
        service.acknowledgeRecoveryKey()
        service.finishOnboarding()
        return key
    }

    @Test func startsWithoutVault() {
        let service = makeService(root: makeRoot())
        guard case .noVault = service.state else {
            Issue.record("expected noVault")
            return
        }
    }

    @Test func existingVaultStartsLocked() async {
        let root = makeRoot()
        await onboard(makeService(root: root))
        let service = makeService(root: root)
        guard case .locked = service.state else {
            Issue.record("expected locked")
            return
        }
    }

    @Test func onboardingCreatesVaultAndUnlocks() async throws {
        let root = makeRoot()
        let service = makeService(root: root)
        service.beginOnboarding()
        guard case .onboarding = service.state else {
            Issue.record("expected onboarding")
            return
        }

        #expect(await service.createVault(password: Self.password) == nil)
        #expect(VaultService.vaultExists(at: root))
        let key = try #require(service.pendingRecoveryKey)
        #expect(key.split(separator: "-").count == 14)
        // The vault stays in onboarding until the key is acknowledged.
        service.finishOnboarding()
        guard case .onboarding = service.state else {
            Issue.record("left onboarding early")
            return
        }

        service.acknowledgeRecoveryKey()
        #expect(service.pendingRecoveryKey == nil)
        service.finishOnboarding()
        #expect(service.isUnlocked)
    }

    @Test func lockAndUnlockWithPassword() async {
        let service = makeService(root: makeRoot())
        await onboard(service)
        service.lock()
        guard case .locked = service.state else {
            Issue.record("expected locked")
            return
        }

        #expect(await service.unlock(password: "wrong password") == .wrongPassword)
        #expect(!service.isUnlocked)
        #expect(await service.unlock(password: Self.password) == .unlocked)
        #expect(service.isUnlocked)
    }

    @Test func lockDropsKeysInHandle() async throws {
        let service = makeService(root: makeRoot())
        await onboard(service)
        guard case .unlocked(let handle) = service.state else {
            Issue.record("not open")
            return
        }
        service.lock()
        #expect(handle.isLocked())
    }

    @Test func recoveryKeyUnlocks() async {
        let service = makeService(root: makeRoot())
        let key = await onboard(service)
        service.lock()
        guard case .failed = await service.unlock(recoveryKey: "not a key") else {
            Issue.record("expected failure")
            return
        }
        #expect(await service.unlock(recoveryKey: key) == .unlocked)
    }

    @Test func duressPasswordLooksLikeNormalUnlock() async throws {
        let service = makeService(root: makeRoot())
        await onboard(service)
        guard case .unlocked(let handle) = service.state else {
            Issue.record("not open")
            return
        }
        try handle.setDuress(password: Self.password, duressPassword: "synthetic duress passphrase")
        service.lock()
        #expect(await service.unlock(password: "synthetic duress passphrase") == .unlocked)
        #expect(service.isUnlocked)
    }

    @Test func autoLockSkippedWhileRecoveryKeyIsShown() async {
        let service = makeService(root: makeRoot())
        service.beginOnboarding()
        _ = await service.createVault(password: Self.password)
        service.lockIfNeeded()
        guard case .onboarding = service.state else {
            Issue.record("locked too early")
            return
        }
        #expect(service.pendingRecoveryKey != nil)

        service.acknowledgeRecoveryKey()
        service.lockIfNeeded()
        guard case .locked = service.state else {
            Issue.record("expected locked")
            return
        }
    }

    @Test func lockIfNeededLocksUnlockedVault() async {
        let service = makeService(root: makeRoot())
        await onboard(service)
        service.lockIfNeeded()
        guard case .locked = service.state else {
            Issue.record("expected locked")
            return
        }
    }

    @Test func inactivityTimeoutLocks() async throws {
        let service = makeService(root: makeRoot(), timeout: .milliseconds(150))
        await onboard(service)
        #expect(service.isUnlocked)
        try await Task.sleep(for: .milliseconds(700))
        guard case .locked = service.state else {
            Issue.record("expected locked")
            return
        }
    }

    @Test func rootIsCreatedWithCompleteProtection() throws {
        let root = makeRoot()
        try VaultService.prepareRoot(root)
        var isDir: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: root.path, isDirectory: &isDir) && isDir.boolValue)
        try VaultService.prepareRoot(root)
    }

    @Test func errorsMapToMessages() {
        #expect(VaultService.message(for: ZeError.WrongRecoveryKey).contains("recovery key"))
        #expect(VaultService.message(for: ZeError.HeaderTampered).contains("verified"))
        #expect(!VaultService.message(for: ZeError.Crypto).isEmpty)
    }

    @Test func interruptedOnboardingRotatesAndReviewsRecoveryKey() async throws {
        let root = makeRoot()
        let first = makeService(root: root)
        first.beginOnboarding()
        #expect(await first.createVault(password: Self.password) == nil)
        let oldKey = try #require(first.pendingRecoveryKey)
        #expect(defaults.bool(forKey: VaultService.recoveryConfirmedKey) == false)

        // Simulates a restart before the key was confirmed.
        let service = makeService(root: root)
        guard case .locked = service.state else {
            Issue.record("expected locked")
            return
        }
        #expect(await service.unlock(password: Self.password) == .unlocked)
        guard case .recoveryKeyReview = service.state else {
            Issue.record("expected recoveryKeyReview")
            return
        }
        let newKey = try #require(service.pendingRecoveryKey)
        #expect(newKey != oldKey)

        service.lockIfNeeded()
        guard case .recoveryKeyReview = service.state else {
            Issue.record("locked during key review")
            return
        }

        service.acknowledgeRecoveryKey()
        service.finishOnboarding()
        #expect(service.isUnlocked)
        #expect(defaults.bool(forKey: VaultService.recoveryConfirmedKey))

        service.lock()
        #expect(await service.unlock(recoveryKey: oldKey) != .unlocked)
        #expect(await service.unlock(recoveryKey: newKey) == .unlocked)
    }
}

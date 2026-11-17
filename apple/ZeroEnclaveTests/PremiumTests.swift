import Foundation
import Testing
import ZeroEnclaveCore

@testable import ZeroEnclave

/// Stand-in for the Secure Enclave key store; keeps a fixed 32-byte key in memory.
final class FakeBiometricKeyStore: BiometricKeyStore, @unchecked Sendable {
    enum Outcome { case ok, cancelled, invalidated, mismatch, lockout, failed }

    private let lock = NSLock()
    private var stored: Data?
    private var outcome = Outcome.ok

    static let key = Data(repeating: 0x42, count: 32)

    var hasKey: Bool { lock.withLock { stored != nil } }
    var isAvailable: Bool { availability == .available }
    var availability: BiometricAvailability { lock.withLock { state } }
    private var state = BiometricAvailability.available

    func setAvailability(_ value: BiometricAvailability) { lock.withLock { state = value } }

    func setOutcome(_ value: Outcome) { lock.withLock { outcome = value } }

    func createKey() throws -> Data {
        lock.withLock { stored = Self.key }
        return Self.key
    }

    func loadKey(reason: String) throws -> Data {
        try lock.withLock {
            switch outcome {
            case .cancelled: throw BiometricKeyError.cancelled
            case .mismatch: throw BiometricKeyError.mismatch
            case .lockout: throw BiometricKeyError.lockout
            case .failed: throw BiometricKeyError.failed
            case .invalidated:
                stored = nil
                throw BiometricKeyError.invalidated
            case .ok:
                guard let stored else { throw BiometricKeyError.invalidated }
                return stored
            }
        }
    }

    func deleteKey() { lock.withLock { stored = nil } }
}

/// Stand-in for the Secure Enclave PIN store: the secret opens only with the stored PIN, and
/// every attempt removes it first, like the real store.
final class FakePinStore: PinKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: (pin: String, secret: Data)?
    private var paused = false

    static let secret = Data(repeating: 0x24, count: 32)

    var hasKey: Bool { lock.withLock { stored != nil } }
    var isPaused: Bool { lock.withLock { stored != nil && paused } }

    func createKey(pin: String) throws -> Data {
        lock.withLock {
            stored = (pin, Self.secret)
            paused = false
        }
        return Self.secret
    }

    func loadKey(pin: String) throws -> Data {
        try lock.withLock {
            guard let current = stored, !paused else { throw PinKeyError.invalidated }
            paused = true
            guard current.pin == pin else { throw PinKeyError.wrongPin }
            paused = false
            return current.secret
        }
    }

    func pause() { lock.withLock { paused = true } }
    func resume() { lock.withLock { paused = false } }

    func deleteKey() {
        lock.withLock {
            stored = nil
            paused = false
        }
    }
}

/// In-memory stand-in for the Keychain counter; a second service sharing it models an app restart.
final class FakeFailureCounter: BiometricFailureCounter, @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    var count: Int { lock.withLock { value } }

    @discardableResult func recordFailure() -> Int {
        lock.withLock {
            value += 1
            return value
        }
    }

    func reset() { lock.withLock { value = 0 } }
}

/// Adjustable wall clock for the trial.
final class TrialClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date(timeIntervalSince1970: 1_800_000_000)

    var now: Date { lock.withLock { value } }
    func advance(days: Int) { lock.withLock { value.addTimeInterval(Double(days) * 86_400) } }
}

/// Mutable `(bootTime, now)` source for the service.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var values: (UInt64, UInt64) = (1_000, 2_000_000)

    var current: (UInt64, UInt64) { lock.withLock { values } }
    func set(boot: UInt64, now: UInt64) { lock.withLock { values = (boot, now) } }
}

@MainActor
struct PremiumTests {
    private static let password = "synthetic test passphrase"
    private static let duress = "synthetic duress passphrase"

    private let suite = "ze-test-\(UUID().uuidString)"
    private let store = FakeBiometricKeyStore()
    private let clock = TestClock()
    private let counter = FakeFailureCounter()
    private let pinStore = FakePinStore()

    private var defaults: UserDefaults { UserDefaults(suiteName: suite)! }

    private func makeRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appending(path: "ze-test-\(UUID().uuidString)", directoryHint: .isDirectory)
            .appending(path: "Vault", directoryHint: .isDirectory)
    }

    private func makeService(root: URL) -> VaultService {
        let clock = clock
        return VaultService(
            root: root, defaults: defaults, defaultsDomain: suite, biometricStore: store,
            failureCounter: counter, pinStore: pinStore, clock: { clock.current },
            calibrate: { kdfDefault() })
    }

    private func unlockedService(root: URL) async -> VaultService {
        let service = makeService(root: root)
        service.beginOnboarding()
        _ = await service.createVault(password: Self.password)
        service.acknowledgeRecoveryKey()
        service.finishOnboarding()
        return service
    }

    // MARK: Entitlements

    @Test func earlyBirdTrialLastsSixMonthsOnce() {
        let defaults = defaults
        let clock = TrialClock()
        let store = MemoryTrialStore()
        let entitlements = Entitlements(defaults: defaults, trialStore: store, extraSources: [], now: { clock.now })
        for feature in Feature.allCases { #expect(!entitlements.isUnlocked(feature)) }
        entitlements.activatePreRelease()
        for feature in Feature.allCases { #expect(entitlements.isUnlocked(feature)) }
        // Survives a reinstall: the activation is in the keychain, not only in the defaults.
        let fresh = UserDefaults(suiteName: "ze-relaunch-\(UUID().uuidString)")!
        #expect(Entitlements(defaults: fresh, trialStore: store, extraSources: [], now: { clock.now }).hasPremium)

        clock.advance(days: PreReleaseSource.trialDays - 1)
        #expect(entitlements.hasPremium)
        clock.advance(days: 2)
        entitlements.reload()
        #expect(!entitlements.hasPremium && entitlements.preReleaseExpired)
        entitlements.activatePreRelease()
        #expect(!entitlements.hasPremium)
    }

    // MARK: Paywall bypass

    @Test func clockRollbackDoesNotReviveTheTrial() {
        let clock = TrialClock()
        let entitlements = Entitlements(defaults: defaults, trialStore: MemoryTrialStore(), extraSources: [], now: { clock.now })
        entitlements.activatePreRelease()
        clock.advance(days: PreReleaseSource.trialDays + 1)
        entitlements.reload()
        #expect(!entitlements.hasPremium)
        // The user sets the device date back.
        clock.advance(days: -100)
        entitlements.reload()
        #expect(!entitlements.hasPremium)
        #expect(entitlements.preReleaseExpired)
    }

    @Test func reinstallDoesNotRestartTheTrial() {
        let clock = TrialClock()
        let store = MemoryTrialStore()
        let first = Entitlements(defaults: defaults, trialStore: store, extraSources: [], now: { clock.now })
        first.activatePreRelease()
        clock.advance(days: PreReleaseSource.trialDays + 1)
        // Deleting the app wipes its defaults; a fresh install activates again.
        let fresh = UserDefaults(suiteName: "ze-reinstall-\(UUID().uuidString)")!
        let reinstalled = Entitlements(defaults: fresh, trialStore: store, extraSources: [], now: { clock.now })
        reinstalled.activatePreRelease()
        #expect(!reinstalled.hasPremium)
        #expect(reinstalled.preReleaseExpired)
    }

    @Test func downloadDateBoundsTheTrial() {
        let clock = TrialClock()
        let store = MemoryTrialStore()
        // Downloaded 100 days ago; activating today leaves the remaining 83 days.
        store.set(clock.now.addingTimeInterval(-100 * 86_400), for: .download)
        let entitlements = Entitlements(defaults: defaults, trialStore: store, extraSources: [], now: { clock.now })
        #expect(!entitlements.hasPremium && !entitlements.preReleaseExpired)
        entitlements.activatePreRelease()
        #expect(entitlements.hasPremium)
        clock.advance(days: PreReleaseSource.trialDays - 100 - 1)
        entitlements.reload()
        #expect(entitlements.hasPremium)
        clock.advance(days: 2)
        entitlements.reload()
        #expect(!entitlements.hasPremium && entitlements.preReleaseExpired)
    }

    @Test func windowOverBeforeActivationCannotBeStarted() {
        let clock = TrialClock()
        let store = MemoryTrialStore()
        store.set(clock.now.addingTimeInterval(-200 * 86_400), for: .download)
        let entitlements = Entitlements(defaults: defaults, trialStore: store, extraSources: [], now: { clock.now })
        #expect(entitlements.preReleaseExpired)
        entitlements.activatePreRelease()
        #expect(!entitlements.hasPremium)
    }

    @Test func keychainStoreRoundTrip() {
        let service = "ze-test-trial-\(UUID().uuidString)"
        let date = Date(timeIntervalSince1970: 1_800_000_123)
        KeychainTrialStore(service: service).set(date, for: .lastSeen)
        #expect(KeychainTrialStore(service: service).date(.lastSeen) == date)
        let later = date.addingTimeInterval(3_600)
        KeychainTrialStore(service: service).set(later, for: .lastSeen)
        #expect(KeychainTrialStore(service: service).date(.lastSeen) == later)
    }

    @Test func lifetimeTestersGetSixMonthsFromUpdate() {
        let defaults = defaults
        defaults.set(true, forKey: PreReleaseSource.defaultsKey)
        let clock = TrialClock()
        let entitlements = Entitlements(defaults: defaults, trialStore: MemoryTrialStore(), extraSources: [], now: { clock.now })
        #expect(entitlements.hasPremium)
        clock.advance(days: PreReleaseSource.trialDays + 1)
        entitlements.reload()
        #expect(!entitlements.hasPremium)
    }

    @Test func anySourceCanGrant() {
        struct Always: EntitlementSource { func grants(_ feature: Feature) -> Bool { true } }
        let entitlements = Entitlements(defaults: defaults, trialStore: MemoryTrialStore(), extraSources: [Always()])
        #expect(entitlements.isUnlocked(.themes))
    }

    @Test func storeSourceGrantsNothingYet() {
        let source = StoreSource()
        #expect(StoreSource.productID == "com.zeroenclave.app.premium")
        for feature in Feature.allCases { #expect(!source.grants(feature)) }
    }

    @Test func gateShowsSheetWhenLocked() {
        let entitlements = Entitlements(defaults: defaults, trialStore: MemoryTrialStore(), extraSources: [])
        let gate = PremiumGate()
        var ran = false
        #expect(!gate.perform(.duressPassword, entitlements: entitlements) { ran = true })
        #expect(gate.isPresentingRequired && !ran)
        #expect(gate.requested == .duressPassword)
        gate.isPresentingRequired = false
        entitlements.activatePreRelease()
        #expect(gate.perform(.duressPassword, entitlements: entitlements) { ran = true })
        #expect(!gate.isPresentingRequired && ran)
    }

    @Test func trashRestoreIsGated() {
        let entitlements = Entitlements(defaults: defaults, trialStore: MemoryTrialStore(), extraSources: [])
        let gate = PremiumGate()
        var restored = false
        #expect(!gate.perform(.trashRestore, entitlements: entitlements) { restored = true })
        #expect(gate.isPresentingRequired && !restored)
        gate.isPresentingRequired = false
        entitlements.activatePreRelease()
        #expect(gate.perform(.trashRestore, entitlements: entitlements) { restored = true })
        #expect(restored && !gate.isPresentingRequired)
    }

    // MARK: Duress state

    @Test func duressStateFollowsCore() async {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        #expect(!service.duressEnabled)
        #expect(await service.setDuress(masterPassword: Self.password, duress: Self.duress) == nil)
        #expect(service.duressEnabled)
        service.lock()
        #expect(await service.unlock(password: Self.password) == .unlocked)
        #expect(service.duressEnabled)
        #expect(await service.disableDuress(masterPassword: Self.password) == nil)
        #expect(!service.duressEnabled)
        #expect(await service.setDuress(masterPassword: Self.password, duress: Self.duress) == nil)
        #expect(await service.changePassword(old: Self.password, new: "another synthetic passphrase") == nil)
        #expect(!service.duressEnabled)
    }

    @Test func unlockPathChangesNeedTheMasterPassword() async {
        let service = await unlockedService(root: makeRoot())
        #expect(await service.setDuress(masterPassword: "wrong", duress: Self.duress) != nil)
        #expect(!service.duressEnabled)
        #expect(await service.setDuress(masterPassword: Self.password, duress: Self.duress) == nil)
        #expect(await service.disableDuress(masterPassword: Self.duress) != nil)
        #expect(service.duressEnabled)
    }

    @Test func changePasswordTurnsOffFaceIDAndPin() async {
        let service = await unlockedService(root: makeRoot())
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        #expect(await service.enablePin(password: Self.password, pin: Self.pin) == nil)
        #expect(service.biometricEnabled && service.pinEnabled)
        #expect(await service.changePassword(old: Self.password, new: "another synthetic passphrase") == nil)
        #expect(!service.biometricEnabled)
        #expect(!service.pinEnabled)
    }

    // MARK: Read-only

    @Test func deletedLocalStateOpensReadOnlyUntilConfirmed() async throws {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        guard case .unlocked(let handle) = service.state else {
            Issue.record("not open")
            return
        }
        _ = try handle.createAlbum(name: "Trips")
        service.lock()
        try FileManager.default.removeItem(at: root.appending(path: "local/state.zeo"))
        #expect(await service.unlock(password: Self.password) == .unlocked)
        #expect(service.isReadOnly)
        #expect(await service.acceptCurrentState(password: "wrong") != nil)
        #expect(service.isReadOnly)
        #expect(await service.acceptCurrentState(password: Self.password) == nil)
        #expect(!service.isReadOnly)
    }

    // MARK: PIN

    private static let pin = "482916"

    private func lockedWithPin() async -> VaultService {
        let service = await unlockedService(root: makeRoot())
        #expect(await service.enablePin(password: Self.password, pin: Self.pin) == nil)
        service.lock()
        return service
    }

    @Test func pinRoundTrip() async {
        let service = await unlockedService(root: makeRoot())
        #expect(!service.pinEnabled)
        #expect(await service.enablePin(password: "wrong", pin: Self.pin) != nil)
        #expect(await service.enablePin(password: Self.password, pin: "12345") != nil)
        #expect(!service.pinEnabled && !pinStore.hasKey)
        #expect(await service.enablePin(password: Self.password, pin: Self.pin) == nil)
        #expect(service.pinEnabled && pinStore.hasKey)

        service.lock()
        #expect(await service.unlock(pin: Self.pin) == .unlocked)
        service.lock()
        #expect(await service.unlock(pin: Self.pin) == .unlocked)
        #expect(await service.disablePin() == nil)
        #expect(!service.pinEnabled && !pinStore.hasKey)
    }

    @Test func wrongPinPausesUntilPassword() async {
        let service = await lockedWithPin()
        #expect(await service.unlock(pin: "000000") == .failed(VaultService.wrongPinMessage))
        #expect(service.pinEnabled && service.pinPaused && pinStore.isPaused)
        #expect(await service.unlock(pin: Self.pin) == .cancelled)
        #expect(await service.unlock(password: Self.password) == .unlocked)
        #expect(service.pinEnabled && !service.pinPaused)
        service.lock()
        #expect(await service.unlock(pin: Self.pin) == .unlocked)
    }

    @Test func pinPauseSurvivesRestart() async {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        #expect(await service.enablePin(password: Self.password, pin: Self.pin) == nil)
        service.lock()
        #expect(await service.unlock(pin: "999999") != .unlocked)
        let restarted = makeService(root: root)
        #expect(restarted.pinPaused)
        #expect(await restarted.unlock(pin: Self.pin) == .cancelled)
    }

    @Test func malformedPinDoesNotUseTheAttempt() async {
        let service = await lockedWithPin()
        #expect(await service.unlock(pin: "12345") == .cancelled)
        #expect(await service.unlock(pin: "12345a") == .cancelled)
        #expect(service.pinEnabled)
        #expect(await service.unlock(pin: Self.pin) == .unlocked)
    }

    @Test func manualLockPausesPinUntilPassword() async {
        let service = await unlockedService(root: makeRoot())
        #expect(await service.enablePin(password: Self.password, pin: Self.pin) == nil)
        service.lockManually()
        #expect(service.pinPaused)
        #expect(await service.unlock(pin: Self.pin) == .cancelled)
        #expect(service.pinEnabled)
        #expect(await service.unlock(password: Self.password) == .unlocked)
        #expect(!service.pinPaused)
        service.lock()
        #expect(await service.unlock(pin: Self.pin) == .unlocked)
    }

    @Test func pinNeedsPasswordAfterRestartButStaysOn() async {
        let service = await lockedWithPin()
        let (boot, now) = clock.current
        clock.set(boot: boot + 60, now: now + 60)
        guard case .failed = await service.unlock(pin: Self.pin) else {
            Issue.record("expected the expired PIN to fail")
            return
        }
        #expect(service.pinEnabled)
        #expect(await service.unlock(password: Self.password) == .unlocked)
        service.lock()
        #expect(await service.unlock(pin: Self.pin) == .unlocked)
    }

    @Test func duressRemovesPinKey() async {
        let service = await unlockedService(root: makeRoot())
        #expect(await service.setDuress(masterPassword: Self.password, duress: Self.duress) == nil)
        #expect(await service.enablePin(password: Self.password, pin: Self.pin) == nil)
        service.lock()
        #expect(await service.unlock(password: Self.duress) == .unlocked)
        #expect(!service.pinEnabled && !pinStore.hasKey)
    }

    // MARK: Face ID

    @Test func faceIDRoundTrip() async {
        let service = await unlockedService(root: makeRoot())
        #expect(!service.biometricEnabled)
        #expect(await service.enableBiometrics(password: "wrong") != nil)
        #expect(!service.biometricEnabled && !store.hasKey)
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        #expect(service.biometricEnabled && store.hasKey)

        service.lock()
        #expect(await service.unlockWithBiometrics() == .unlocked)
        #expect(service.isUnlocked)

        service.lock()
        store.setOutcome(.cancelled)
        #expect(await service.unlockWithBiometrics() == .cancelled)
        #expect(service.biometricEnabled)
    }

    private func lockedWithFaceID() async -> VaultService {
        let service = await unlockedService(root: makeRoot())
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        service.lock()
        return service
    }

    @Test func faceIDBlockedAfterTwoMismatches() async {
        let service = await lockedWithFaceID()
        store.setOutcome(.mismatch)
        // The first non-match only counts; the prompt simply closes.
        #expect(await service.unlockWithBiometrics() == .cancelled)
        #expect(counter.count == 1 && !service.biometricBlocked)

        guard case .failed = await service.unlockWithBiometrics() else {
            Issue.record("expected failure")
            return
        }
        #expect(counter.count == 2 && service.biometricBlocked)

        // Blocked: even a matching face is not evaluated any more.
        store.setOutcome(.ok)
        #expect(await service.unlockWithBiometrics() == .cancelled)
        #expect(!service.isUnlocked)
    }

    @Test func manualLockPausesFaceIDUntilPassword() async {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        service.lockManually()
        #expect(service.biometricBlocked)
        store.setOutcome(.ok)
        #expect(await service.unlockWithBiometrics() == .cancelled)
        #expect(!service.isUnlocked)
    }

    @Test func cancelDoesNotCountAsFailure() async {
        let service = await lockedWithFaceID()
        store.setOutcome(.cancelled)
        for _ in 0..<5 { #expect(await service.unlockWithBiometrics() == .cancelled) }
        #expect(counter.count == 0 && !service.biometricBlocked)
    }

    @Test func passwordUnlockResetsCounter() async {
        let service = await lockedWithFaceID()
        store.setOutcome(.mismatch)
        for _ in 0..<3 { _ = await service.unlockWithBiometrics() }
        #expect(service.biometricBlocked)

        #expect(await service.unlock(password: Self.password) == .unlocked)
        #expect(counter.count == 0 && !service.biometricBlocked)
    }

    @Test func successfulFaceIDResetsCounter() async {
        let service = await lockedWithFaceID()
        store.setOutcome(.mismatch)
        _ = await service.unlockWithBiometrics()
        #expect(counter.count == 1)
        store.setOutcome(.ok)
        #expect(await service.unlockWithBiometrics() == .unlocked)
        #expect(counter.count == 0)
    }

    @Test func blockSurvivesRestartAndDisableClearsIt() async {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        service.lock()
        store.setOutcome(.mismatch)
        for _ in 0..<3 { _ = await service.unlockWithBiometrics() }

        // New service with the same persisted counter.
        let restarted = makeService(root: root)
        #expect(restarted.biometricBlocked)

        #expect(await restarted.unlock(password: Self.password) == .unlocked)
        #expect(await restarted.disableBiometrics() == nil)
        #expect(counter.count == 0 && !restarted.biometricBlocked)
    }

    @Test func passwordUnlockRefreshesSlotAndCounter() async {
        let service = await lockedWithFaceID()
        store.setOutcome(.mismatch)
        for _ in 0..<3 { _ = await service.unlockWithBiometrics() }
        #expect(service.biometricBlocked)

        // New boot: the old slot is expired until a password unlock re-arms it.
        clock.set(boot: 5_000, now: 2_000_100)
        store.setOutcome(.ok)
        #expect(await service.unlock(password: Self.password) == .unlocked)
        #expect(counter.count == 0 && !service.biometricBlocked)
        service.lock()
        #expect(await service.unlockWithBiometrics() == .unlocked)
    }

    @Test func systemLockoutHasOwnMessageAndIsNotCounted() async {
        let service = await lockedWithFaceID()
        store.setOutcome(.lockout)
        guard case .failed(let text) = await service.unlockWithBiometrics() else {
            Issue.record("expected failure")
            return
        }
        #expect(text.contains("passcode") && counter.count == 0)
    }

    @Test func transientFaceIDErrorsAreSilentAndNotCounted() async {
        let service = await lockedWithFaceID()
        for outcome in [FakeBiometricKeyStore.Outcome.failed, .cancelled] {
            store.setOutcome(outcome)
            guard case .cancelled = await service.unlockWithBiometrics() else {
                Issue.record("expected a silent cancel for \(outcome)")
                return
            }
        }
        #expect(counter.count == 0 && !service.biometricBlocked)
    }

    @Test func unavailableStatesAreReportedWithoutPrompt() async {
        let service = await lockedWithFaceID()
        store.setOutcome(.mismatch)
        for state in [BiometricAvailability.lockedOut, .notEnrolled, .unavailable] {
            store.setAvailability(state)
            guard case .failed(let text) = await service.unlockWithBiometrics() else {
                Issue.record("expected failure")
                return
            }
            #expect(text == VaultService.message(for: state))
            #expect(service.biometricAvailability == state)
        }
        #expect(counter.count == 0)
    }

    @Test func faceIDExpiresAfterRestartAndSevenDays() async {
        let service = await unlockedService(root: makeRoot())
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        service.lock()

        clock.set(boot: 5_000, now: 2_000_100)
        guard case .failed(let text) = await service.unlockWithBiometrics() else {
            Issue.record("expected failure after restart")
            return
        }
        #expect(text.contains("7 days"))
        #expect(service.biometricEnabled)

        // A password unlock refreshes the slot for the new boot.
        #expect(await service.unlock(password: Self.password) == .unlocked)
        service.lock()
        #expect(await service.unlockWithBiometrics() == .unlocked)

        service.lock()
        clock.set(boot: 5_000, now: 2_000_100 + 8 * 86_400)
        guard case .failed = await service.unlockWithBiometrics() else {
            Issue.record("expected failure after 7 days")
            return
        }
        #expect(service.biometricEnabled)
    }

    @Test func invalidatedKeyTurnsFaceIDOff() async {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        service.lock()
        store.setOutcome(.invalidated)
        guard case .failed = await service.unlockWithBiometrics() else {
            Issue.record("expected failure")
            return
        }
        #expect(!service.biometricEnabled && !store.hasKey)
        #expect(!vaultIsBiometricEnabled(root: root.path))
        #expect(await service.unlock(password: Self.password) == .unlocked)
    }

    @Test func disableFaceIDRemovesKeyAndSlot() async {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        #expect(await service.disableBiometrics() == nil)
        #expect(!service.biometricEnabled && !store.hasKey)
        #expect(!vaultIsBiometricEnabled(root: root.path))
    }

    @Test func duressUnlockSilentlyDeletesKey() async {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        #expect(await service.setDuress(masterPassword: Self.password, duress: Self.duress) == nil)
        #expect(await service.enableBiometrics(password: Self.password) == nil)
        service.lock()
        #expect(await service.unlock(password: Self.duress) == .unlocked)
        #expect(!store.hasKey && !service.biometricEnabled)
        #expect(!vaultIsBiometricEnabled(root: root.path))
    }

    @Test func biometricFFIWithFixedKey() throws {
        let root = makeRoot()
        try VaultService.prepareRoot(root)
        let handle = try vaultCreate(root: root.path, password: Self.password, params: kdfDefault()).handle
        let key = FakeBiometricKeyStore.key
        #expect(throws: ZeError.self) { try handle.enableBiometric(password: Self.password, bioKey: Data([1]), bootTime: 1, now: 2) }
        try handle.enableBiometric(password: Self.password, bioKey: key, bootTime: 1, now: 2)
        #expect(handle.isBiometricEnabled())
        handle.lock()
        #expect(throws: ZeError.self) {
            try vaultUnlockBiometric(root: root.path, bioKey: Data(repeating: 1, count: 32), bootTime: 1, now: 3)
        }
        #expect(throws: ZeError.self) { try vaultUnlockBiometric(root: root.path, bioKey: key, bootTime: 2, now: 3) }
        let reopened = try vaultUnlockBiometric(root: root.path, bioKey: key, bootTime: 1, now: 3)
        #expect(!reopened.isLocked())
    }

    // MARK: Erase

    @Test func eraseConfirmationNeedsPasswordAndWord() {
        #expect(!EraseVaultView.canErase(password: "", word: "ERASE"))
        #expect(!EraseVaultView.canErase(password: "x", word: "erase"))
        #expect(!EraseVaultView.canErase(password: "x", word: ""))
        #expect(EraseVaultView.canErase(password: "x", word: "ERASE"))
    }

    @Test func eraseDestroysVaultAndResetsApp() async throws {
        let root = makeRoot()
        let service = await unlockedService(root: root)
        let defaults = defaults
        defaults.set(true, forKey: PreReleaseSource.defaultsKey)
        #expect(await service.enableBiometrics(password: Self.password) == nil)

        #expect(await service.eraseVault(password: "wrong") != nil)
        #expect(service.isUnlocked)
        #expect(VaultService.vaultExists(at: root))
        #expect(store.hasKey)

        #expect(await service.eraseVault(password: Self.password) == nil)
        guard case .noVault = service.state else {
            Issue.record("expected noVault")
            return
        }
        #expect(!VaultService.vaultExists(at: root))
        #expect((try? FileManager.default.contentsOfDirectory(atPath: root.path))?.isEmpty ?? true)
        #expect(!store.hasKey && !service.biometricEnabled && !service.duressEnabled)
        #expect(!defaults.bool(forKey: PreReleaseSource.defaultsKey))
        #expect(!defaults.bool(forKey: VaultService.recoveryConfirmedKey))

        // A new vault can be created afterwards.
        service.beginOnboarding()
        #expect(await service.createVault(password: Self.password) == nil)
    }
}

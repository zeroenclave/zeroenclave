import Foundation
import Observation
import ZeroEnclaveCore

/// Result of an unlock attempt; carries no vault content.
enum UnlockAttempt: Equatable {
    case unlocked
    case wrongPassword
    /// The user dismissed the Face ID prompt; nothing to show.
    case cancelled
    case failed(String)
}

/// Failure with a user-facing message.
struct VaultFailure: Error, Equatable {
    let message: String
    /// The backup belongs to another vault; it can only replace this one.
    let isDifferentVault: Bool
    init(_ message: String, isDifferentVault: Bool = false) {
        self.message = message
        self.isDifferentVault = isDifferentVault
    }
}

/// Owns the vault lifecycle: `noVault -> onboarding -> locked <-> unlocked`.
@MainActor
@Observable
final class VaultService {
    enum State {
        case noVault
        case onboarding
        /// Unlocked after an interrupted onboarding; a fresh recovery key must be confirmed first.
        case recoveryKeyReview
        case locked
        case unlocked(VaultHandle)

        /// Whether the screen can show private content (photos, recovery key) that needs the
        /// privacy cover in the app switcher. The unlock and welcome screens show none.
        var needsPrivacyCover: Bool {
            switch self {
            case .noVault, .locked: false
            case .onboarding, .recoveryKeyReview, .unlocked: true
            }
        }

        var isOnboardingStep: Bool {
            switch self {
            case .onboarding, .recoveryKeyReview: true
            default: false
            }
        }
    }

    nonisolated static let recoveryConfirmedKey = "recoveryKeyConfirmed"
    nonisolated static let vaultFileName = "vault.zev"
    nonisolated static let inactivityMinutesKey = "inactivityTimeoutMinutes"
    nonisolated static let inactivityChoices = [1, 5, 15]
    static let defaultInactivityTimeout: Duration = .seconds(300)
    nonisolated private static let calibrationTargetMs: UInt32 = 800

    private(set) var state: State {
        didSet { PrivacyWindowController.isNeeded = state.needsPrivacyCover }
    }
    /// Shown once during onboarding; cleared by `finishOnboarding`.
    private(set) var pendingRecoveryKey: String?
    private(set) var isWorking = false
    private(set) var isCalibrating = false
    private(set) var throttle = UnlockThrottle()
    /// Inactivity auto-lock in minutes, persisted in the defaults.
    private(set) var inactivityMinutes: Int
    /// Shown on the unlock screen after the vault was locked during an import.
    private(set) var lockNotice: String?
    /// Duress state of the open vault, read from the encrypted core state.
    private(set) var duressEnabled = false
    /// The core found vault files that do not match its local state (possible rollback).
    /// Viewing and export work; changes need `acceptCurrentState`.
    private(set) var isReadOnly = false
    /// Face ID is usable: the keychain item and the core slot both exist.
    private(set) var biometricEnabled = false
    /// True once Face ID failed `maxBiometricFailures` times; only a password or recovery unlock clears it.
    private(set) var biometricBlocked = false
    /// System state of Face ID; refreshed on lock and before every prompt.
    private(set) var biometricAvailability = BiometricAvailability.available
    nonisolated static let maxBiometricFailures = 2
    /// PIN unlock is usable: the keychain item and the core slot both exist.
    private(set) var pinEnabled = false
    /// After a wrong PIN or a manual lock the PIN waits for the next password or recovery unlock.
    /// Stored in the core slot and the keychain, not in app defaults.
    private(set) var pinPaused = false
    /// Decrypted images of the unlocked session; emptied on every lock.
    @ObservationIgnored let imageCache = DecryptedImageCache()

    @ObservationIgnored private let root: URL
    @ObservationIgnored private let defaults: UserDefaults
    /// Persistent domain removed when the vault is erased; nil leaves the defaults alone.
    @ObservationIgnored private let defaultsDomain: String?
    @ObservationIgnored private let biometricStore: BiometricKeyStore
    @ObservationIgnored private let failureCounter: BiometricFailureCounter
    @ObservationIgnored private let pinStore: PinKeyStore
    /// Returns `(bootTime, now)` in Unix seconds.
    @ObservationIgnored private let clock: @Sendable () -> (UInt64, UInt64)
    /// Fixed timeout from the initializer (tests); cleared once the user picks a value.
    @ObservationIgnored private var timeoutOverride: Duration?
    @ObservationIgnored private let calibrate: @Sendable () -> KdfParams
    @ObservationIgnored private var pendingHandle: VaultHandle?
    @ObservationIgnored private var calibration: Task<KdfParams, Never>?
    @ObservationIgnored private var inactivityTask: Task<Void, Never>?
    @ObservationIgnored private var lastActivity: ContinuousClock.Instant?
    @ObservationIgnored private var playbackStops: [UUID: () -> Void] = [:]

    init(
        root: URL = VaultService.defaultRoot(),
        defaults: UserDefaults = .standard,
        defaultsDomain: String? = Bundle.main.bundleIdentifier,
        biometricStore: BiometricKeyStore = SecureEnclaveKeyStore(),
        failureCounter: BiometricFailureCounter = KeychainBiometricFailureCounter(),
        pinStore: PinKeyStore = SecureEnclavePinStore(),
        clock: @escaping @Sendable () -> (UInt64, UInt64) = { (SystemClock.bootTime(), SystemClock.now()) },
        inactivityTimeout: Duration? = nil,
        calibrate: @escaping @Sendable () -> KdfParams = {
            kdfCalibrate(targetMs: VaultService.calibrationTargetMs)
        }
    ) {
        self.root = root
        self.defaults = defaults
        self.defaultsDomain = defaultsDomain
        self.biometricStore = biometricStore
        self.failureCounter = failureCounter
        self.pinStore = pinStore
        self.clock = clock
        timeoutOverride = inactivityTimeout
        let stored = defaults.integer(forKey: Self.inactivityMinutesKey)
        inactivityMinutes = Self.inactivityChoices.contains(stored) ? stored : 5
        self.calibrate = calibrate
        state = Self.vaultExists(at: root) ? .locked : .noVault
        // didSet does not run during init.
        PrivacyWindowController.isNeeded = state.needsPrivacyCover
        refreshBiometricState()
        refreshPinState()
        biometricBlocked = failureCounter.count >= Self.maxBiometricFailures
        biometricAvailability = biometricStore.availability
    }

    /// Re-reads the system Face ID state (e.g. after the user unlocked with the passcode).
    func refreshBiometricAvailability() {
        biometricAvailability = biometricStore.availability
    }

    /// User-facing explanation for a Face ID state that is not usable; nil if available.
    static func message(for availability: BiometricAvailability) -> String? {
        switch availability {
        case .available: nil
        case .lockedOut:
            String(localized: "iOS has locked Face ID after too many attempts. Lock the device and unlock it with your passcode, then Face ID works again.")
        case .notEnrolled:
            String(localized: "Face ID is not set up on this device. Set it up in the iOS settings or use your master password.")
        case .unavailable:
            String(localized: "Face ID is not available on this device. Use your master password.")
        }
    }

    private var inactivityTimeout: Duration {
        timeoutOverride ?? .seconds(inactivityMinutes * 60)
    }

    static func defaultRoot() -> URL {
        URL.applicationSupportDirectory.appending(path: "Vault", directoryHint: .isDirectory)
    }

    nonisolated static func vaultExists(at root: URL) -> Bool {
        FileManager.default.fileExists(
            atPath: root.appending(path: vaultFileName, directoryHint: .notDirectory).path)
    }

    var isUnlocked: Bool {
        if case .unlocked = state { return true }
        return false
    }

    /// True while the one-time recovery key is held in memory.
    var isHoldingRecoveryKey: Bool { pendingRecoveryKey != nil }

    // MARK: Onboarding

    /// Leaves the welcome screen and starts KDF calibration in the background.
    func beginOnboarding() {
        guard case .noVault = state else { return }
        state = .onboarding
        let calibrate = calibrate
        isCalibrating = true
        calibration = Task.detached(priority: .userInitiated) { calibrate() }
    }

    /// Creates the vault. Returns an error message on failure.
    func createVault(password: String) async -> String? {
        guard case .onboarding = state, pendingHandle == nil, !isWorking else { return nil }
        isWorking = true
        defer { isWorking = false }
        let params = await calibration?.value ?? kdfDefault()
        isCalibrating = false
        let root = root
        do {
            try Self.prepareRoot(root)
            let created = try await Task.detached(priority: .userInitiated) {
                try vaultCreate(root: root.path, password: password, params: params)
            }.value
            defaults.set(false, forKey: Self.recoveryConfirmedKey)
            pendingHandle = created.handle
            pendingRecoveryKey = created.recoveryKey
            return nil
        } catch {
            return Self.message(for: error)
        }
    }

    /// The user confirmed the recovery key; it is dropped from memory.
    func acknowledgeRecoveryKey() {
        defaults.set(true, forKey: Self.recoveryConfirmedKey)
        pendingRecoveryKey = nil
    }

    /// Ends onboarding after the recovery key was confirmed; the vault stays open.
    func finishOnboarding() {
        guard state.isOnboardingStep, !isHoldingRecoveryKey, let handle = pendingHandle else {
            return
        }
        pendingHandle = nil
        open(handle)
    }

    // MARK: Unlock

    func unlock(password: String) async -> UnlockAttempt {
        guard case .locked = state, !isWorking, throttle.remaining() == 0 else {
            return .failed(String(localized: "Please wait before trying again."))
        }
        isWorking = true
        defer { isWorking = false }
        let root = root
        let clock = clock
        do {
            let result = try await Task.detached(priority: .userInitiated) {
                let (boot, now) = clock()
                return try vaultUnlock(root: root.path, password: password, bootTime: boot, now: now)
            }.value
            switch result {
            case .duress(let handle):
                // Duress is indistinguishable from a normal unlock; the core already removed
                // the biometric slot, the Secure Enclave key goes silently.
                biometricStore.deleteKey()
                pinStore.deleteKey()
                resetBiometricFailures()
                refreshPinState()
                open(handle)
                return .unlocked
            case .open(let handle):
                resetBiometricFailures()
                resumePin()
                if !defaults.bool(forKey: Self.recoveryConfirmedKey) {
                    return await reviewRecoveryKey(handle, password: password)
                }
                open(handle)
                return .unlocked
            case .wrongPassword:
                throttle.recordFailure()
                return .wrongPassword
            }
        } catch {
            return .failed(Self.message(for: error))
        }
    }

    func unlock(recoveryKey: String) async -> UnlockAttempt {
        guard case .locked = state, !isWorking else { return .failed("") }
        isWorking = true
        defer { isWorking = false }
        let root = root
        let clock = clock
        do {
            let handle = try await Task.detached(priority: .userInitiated) {
                let (boot, now) = clock()
                return try vaultUnlockRecovery(
                    root: root.path, recoveryKey: recoveryKey, bootTime: boot, now: now)
            }.value
            resetBiometricFailures()
            resumePin()
            open(handle)
            return .unlocked
        } catch {
            return .failed(Self.message(for: error))
        }
    }

    /// Face ID unlock: decrypts `bio_key` with the Secure Enclave key and opens the vault.
    /// Never falls back to the device passcode and never counts as a password attempt.
    func unlockWithBiometrics() async -> UnlockAttempt {
        guard case .locked = state, !isWorking, biometricEnabled, !biometricBlocked else { return .cancelled }
        refreshBiometricAvailability()
        if let text = Self.message(for: biometricAvailability) { return .failed(text) }
        isWorking = true
        defer { isWorking = false }
        let root = root
        let clock = clock
        let store = biometricStore
        do {
            let handle = try await Task.detached(priority: .userInitiated) {
                var key = try store.loadKey(reason: String(localized: "Unlock your vault"))
                defer { key.wipe() }
                let (boot, now) = clock()
                return try vaultUnlockBiometric(
                    root: root.path, bioKey: key, bootTime: boot, now: now)
            }.value
            resetBiometricFailures()
            open(handle)
            return .unlocked
        } catch BiometricKeyError.cancelled {
            return .cancelled
        } catch BiometricKeyError.mismatch, BiometricKeyError.userCancelled {
            // Non-matches and user dismissals count; system/app cancellations do not.
            biometricBlocked = failureCounter.recordFailure() >= Self.maxBiometricFailures
            return biometricBlocked
                ? .failed(String(localized: "Face ID is paused. Enter your master password to use Face ID again."))
                : .cancelled
        } catch BiometricKeyError.lockout {
            // The system lock is its own gate; it adds no in-app failure.
            refreshBiometricAvailability()
            return .failed(Self.message(for: .lockedOut) ?? "")
        } catch BiometricKeyError.notEnrolled {
            refreshBiometricAvailability()
            return .failed(Self.message(for: .notEnrolled) ?? "")
        } catch BiometricKeyError.unavailable {
            refreshBiometricAvailability()
            return .failed(Self.message(for: .unavailable) ?? "")
        } catch BiometricKeyError.invalidated {
            return invalidateBiometrics()
        } catch let error as ZeError {
            switch error {
            case .BiometricExpired:
                return .failed(Self.biometricExpiredMessage)
            case .BiometricInvalid, .NotFound:
                return invalidateBiometrics()
            default:
                return .failed(Self.message(for: error))
            }
        } catch {
            // Face ID stays offered; the user can retry or type the password, no message needed.
            return .cancelled
        }
    }

    /// PIN unlock: one attempt. A wrong PIN pauses PIN unlock until the next password or recovery
    /// unlock; then the same PIN works again. Never counts as a password attempt.
    /// `beforeOpen` runs after the PIN was accepted and before the vault appears, e.g. for feedback.
    func unlock(pin: String, beforeOpen: () async -> Void = {}) async -> UnlockAttempt {
        guard case .locked = state, !isWorking, pinEnabled, !pinPaused, UnlockPin.isValid(pin) else {
            return .cancelled
        }
        isWorking = true
        defer { isWorking = false }
        let root = root
        let clock = clock
        let store = pinStore
        do {
            let handle = try await Task.detached(priority: .userInitiated) {
                var secret = try store.loadKey(pin: pin)
                defer { secret.wipe() }
                let (boot, now) = clock()
                return try vaultUnlockPin(root: root.path, seSecret: secret, pin: pin, bootTime: boot, now: now)
            }.value
            resetBiometricFailures()
            await beforeOpen()
            open(handle)
            return .unlocked
        } catch ZeError.PinExpired {
            return .failed(Self.pinExpiredMessage)
        } catch PinKeyError.invalidated {
            // Key material is gone: PIN unlock cannot work any more.
            pinStore.deleteKey()
            try? vaultRemovePin(root: root.path)
            refreshPinState()
            return .failed(Self.message(for: ZeError.PinInvalid))
        } catch {
            // Whichever side rejected the PIN, both stay paused until the master password.
            pausePin()
            return .failed(Self.wrongPinMessage)
        }
    }

    nonisolated static var wrongPinMessage: String {
        String(localized: "Wrong PIN. Enter your master password; after that the PIN works again.")
    }

    nonisolated private static var pinExpiredMessage: String {
        String(localized: "Enter your master password. PIN unlock needs it after a restart and every 7 days.")
    }

    /// The Secure Enclave key or the slot is unusable: remove both and ask for the password.
    private func invalidateBiometrics() -> UnlockAttempt {
        biometricStore.deleteKey()
        resetBiometricFailures()
        try? vaultRemoveBiometric(root: root.path)
        refreshBiometricState()
        return .failed(
            String(localized: "Face ID was turned off because your biometrics changed. Enter your master password."))
    }

    /// After a successful unlock: Face ID counts from zero.
    private func resetBiometricFailures() {
        failureCounter.reset()
        biometricBlocked = false
    }

    nonisolated private static var biometricExpiredMessage: String {
        String(localized: "Enter your master password. Face ID needs it after a restart and every 7 days.")
    }

    /// The key from an interrupted onboarding was never confirmed: replace it and show the new one.
    private func reviewRecoveryKey(_ handle: VaultHandle, password: String) async -> UnlockAttempt {
        do {
            let key = try await Task.detached(priority: .userInitiated) {
                try handle.rotateRecovery(password: password)
            }.value
            pendingHandle = handle
            pendingRecoveryKey = key
            state = .recoveryKeyReview
            throttle.reset()
            return .unlocked
        } catch {
            handle.lock()
            return .failed(Self.message(for: error))
        }
    }

    // MARK: Locking

    /// Drops the handle; the core wipes all keys. A pending onboarding key is kept.
    /// Manual lock: the next unlock requires the master password once (Face ID is blocked until then).
    func lockManually() {
        while failureCounter.count < Self.maxBiometricFailures {
            failureCounter.recordFailure()
        }
        biometricBlocked = true
        pausePin()
        lock()
    }

    func lock() {
        imageCache.removeAll()
        stopPlayback()
        SnapshotCleaner.removeSnapshots()
        CameraImportSource.removeStale()
        guard case .unlocked(let handle) = state else { return }
        handle.lock()
        state = .locked
        cancelInactivityTimer()
        refreshBiometricAvailability()
    }

    /// Auto-lock entry point for background and memory warnings.
    func lockIfNeeded() {
        imageCache.removeAll()
        stopPlayback()
        guard !isHoldingRecoveryKey else { return }
        if state.isOnboardingStep, let handle = pendingHandle {
            handle.lock()
            pendingHandle = nil
            state = .locked
            return
        }
        lock()
    }

    /// Restarts the inactivity timer while unlocked.
    func noteActivity() {
        guard isUnlocked else { return }
        let now = ContinuousClock.now
        if let last = lastActivity, now - last < .seconds(1), inactivityTask != nil { return }
        lastActivity = now
        let timeout = inactivityTimeout
        inactivityTask?.cancel()
        inactivityTask = Task { [weak self] in
            do { try await Task.sleep(for: timeout) } catch { return }
            self?.lock()
        }
    }

    /// Sets the inactivity auto-lock; ignores values outside `inactivityChoices`.
    func setInactivityMinutes(_ minutes: Int) {
        guard Self.inactivityChoices.contains(minutes) else { return }
        defaults.set(minutes, forKey: Self.inactivityMinutesKey)
        inactivityMinutes = minutes
        timeoutOverride = nil
        lastActivity = nil
        noteActivity()
    }

    // MARK: Playback

    /// Registers a stop action that runs before the vault locks; returns the token to unregister.
    func registerPlayback(stop: @escaping () -> Void) -> UUID {
        let token = UUID()
        playbackStops[token] = stop
        return token
    }

    func unregisterPlayback(_ token: UUID) {
        playbackStops[token] = nil
    }

    private func stopPlayback() {
        let stops = Array(playbackStops.values)
        for stop in stops { stop() }
    }

    // MARK: Settings

    private var unlockedHandle: VaultHandle? {
        if case .unlocked(let handle) = state { return handle }
        return nil
    }

    /// Re-wraps the vault key under a new password with freshly calibrated KDF parameters.
    /// The duress password, Face ID and PIN are turned off by this. Returns an error message.
    func changePassword(old: String, new: String) async -> String? {
        guard let handle = unlockedHandle, !isWorking else { return Self.busyMessage }
        isWorking = true
        isCalibrating = true
        defer {
            isWorking = false
            isCalibrating = false
        }
        let calibrate = calibrate
        let params = await Task.detached(priority: .userInitiated) { calibrate() }.value
        isCalibrating = false
        do {
            try await Task.detached(priority: .userInitiated) {
                try handle.changePassword(old: old, new: new, params: params)
            }.value
            refreshHandleState()
            return nil
        } catch {
            return Self.message(for: error)
        }
    }

    /// Replaces the recovery key; the old one stops working. Returns the new key.
    /// The core verifies the master password before it replaces the key.
    func rotateRecoveryKey(password: String) async -> Result<String, VaultFailure> {
        guard let handle = unlockedHandle, !isWorking else { return .failure(.init(Self.busyMessage)) }
        isWorking = true
        defer { isWorking = false }
        do {
            let key = try await Task.detached(priority: .userInitiated) {
                try handle.rotateRecovery(password: password)
            }.value
            return .success(key)
        } catch {
            return .failure(.init(Self.message(for: error)))
        }
    }

    /// The core verifies the master password first.
    func setDuress(masterPassword: String, duress: String) async -> String? {
        let failure = await withHandle { try $0.setDuress(password: masterPassword, duressPassword: duress) }
        refreshHandleState()
        return failure
    }

    /// The core verifies the master password first.
    func disableDuress(masterPassword: String) async -> String? {
        let failure = await withHandle { try $0.disableDuress(password: masterPassword) }
        refreshHandleState()
        return failure
    }

    /// Ends read-only mode: the owner confirms the vault files as they are.
    func acceptCurrentState(password: String) async -> String? {
        let failure = await withHandle { try $0.acceptCurrentState(password: password) }
        refreshHandleState()
        return failure
    }

    /// Turns Face ID on after the master password was re-entered. Returns an error message.
    func enableBiometrics(password: String) async -> String? {
        guard let handle = unlockedHandle, !isWorking else { return Self.busyMessage }
        isWorking = true
        defer { isWorking = false }
        let clock = clock
        let store = biometricStore
        do {
            try await Task.detached(priority: .userInitiated) {
                // Checked before the key is created; the core checks again.
                try handle.verifyPassword(password: password)
                var key = try store.createKey()
                defer { key.wipe() }
                do {
                    let (boot, now) = clock()
                    try handle.enableBiometric(password: password, bioKey: key, bootTime: boot, now: now)
                } catch {
                    store.deleteKey()
                    throw error
                }
            }.value
            refreshHandleState()
            return nil
        } catch BiometricKeyError.unavailable {
            return String(localized: "Face ID is not available on this device.")
        } catch is BiometricKeyError {
            return String(localized: "Face ID could not be set up. Try again.")
        } catch {
            return Self.message(for: error)
        }
    }

    /// Turns PIN unlock on after the master password was re-entered. Returns an error message.
    func enablePin(password: String, pin: String) async -> String? {
        guard let handle = unlockedHandle, !isWorking else { return Self.busyMessage }
        guard UnlockPin.isValid(pin) else { return String(localized: "Enter six digits.") }
        isWorking = true
        defer { isWorking = false }
        let clock = clock
        let store = pinStore
        do {
            try await Task.detached(priority: .userInitiated) {
                // Checked before the key is created; the core checks again.
                try handle.verifyPassword(password: password)
                var secret = try store.createKey(pin: pin)
                defer { secret.wipe() }
                do {
                    let (boot, now) = clock()
                    try handle.enablePin(password: password, seSecret: secret, pin: pin, bootTime: boot, now: now)
                } catch {
                    store.deleteKey()
                    throw error
                }
            }.value
            refreshHandleState()
            return nil
        } catch is PinKeyError {
            return String(localized: "PIN unlock could not be set up. A device passcode is required.")
        } catch {
            return Self.message(for: error)
        }
    }

    /// Deletes the Secure Enclave key, the keychain item and the core slot.
    func disablePin() async -> String? {
        pinStore.deleteKey()
        let failure = await withHandle { try $0.disablePin() }
        refreshHandleState()
        return failure
    }

    /// Checks the master password of the unlocked vault; false for a wrong or the duress password.
    func verifyPassword(_ password: String) async -> Bool {
        guard let handle = unlockedHandle else { return false }
        return await Task.detached(priority: .userInitiated) {
            (try? handle.verifyPassword(password: password)) != nil
        }.value
    }

    /// Deletes the Secure Enclave key, the keychain item and the core slot.
    func disableBiometrics() async -> String? {
        let store = biometricStore
        store.deleteKey()
        resetBiometricFailures()
        let failure = await withHandle { try $0.disableBiometric() }
        refreshHandleState()
        return failure
    }

    // MARK: Erase

    /// Permanently destroys the vault after the master password was verified, removes the
    /// Secure Enclave key, resets the app defaults and returns to the start screen.
    func eraseVault(password: String) async -> String? {
        guard let handle = unlockedHandle, !isWorking else { return Self.busyMessage }
        isWorking = true
        defer { isWorking = false }
        imageCache.removeAll()
        stopPlayback()
        do {
            try await Task.detached(priority: .userInitiated) { try handle.erase(password: password) }.value
        } catch {
            if !Self.vaultExists(at: root) {
                finishErase()
            } else if handle.isLocked() {
                lock()
            }
            // A wrong password leaves the vault untouched and open.
            return Self.message(for: error)
        }
        finishErase()
        return nil
    }

    private func finishErase() {
        biometricStore.deleteKey()
        pinStore.deleteKey()
        resetBiometricFailures()
        if let defaultsDomain { defaults.removePersistentDomain(forName: defaultsDomain) }
        SnapshotCleaner.removeSnapshots()
        cancelInactivityTimer()
        pendingHandle = nil
        pendingRecoveryKey = nil
        lockNotice = nil
        throttle.reset()
        duressEnabled = false
        biometricEnabled = false
        state = .noVault
    }

    private func withHandle(_ body: @escaping @Sendable (VaultHandle) throws -> Void) async -> String? {
        guard let handle = unlockedHandle, !isWorking else { return Self.busyMessage }
        isWorking = true
        defer { isWorking = false }
        do {
            try await Task.detached(priority: .userInitiated) { try body(handle) }.value
            return nil
        } catch {
            return Self.message(for: error)
        }
    }

    // MARK: Backup

    /// Writes the encrypted backup to `url`; `progress` receives (done, total) on the main actor.
    func exportBackup(
        to url: URL, progress: @escaping @MainActor (UInt64, UInt64) -> Void
    ) async -> String? {
        guard let handle = unlockedHandle else { return Self.busyMessage }
        let callback = ClosureProgress { done, total in
            Task { @MainActor in progress(done, total) }
        }
        do {
            try await Task.detached(priority: .userInitiated) {
                try handle.exportTo(path: url.path, progress: callback)
            }.value
            return nil
        } catch {
            return Self.backupMessage(for: error)
        }
    }

    /// Merges a backup of this vault into the open vault.
    func importBackup(from url: URL, secret: ImportSecret) async -> Result<ImportOutcome, VaultFailure> {
        guard let handle = unlockedHandle else { return .failure(.init(Self.busyMessage)) }
        noteActivity()
        do {
            let outcome = try await Task.detached(priority: .userInitiated) {
                try handle.importInto(path: url.path, secret: secret)
            }.value
            noteActivity()
            // The core turned duress off.
            duressEnabled = handle.isDuressEnabled()
            return .success(outcome)
        } catch {
            var different = false
            if let error = error as? ZeError, case .DifferentVault = error { different = true }
            return .failure(.init(Self.backupMessage(for: error), isDifferentVault: different))
        }
    }

    /// Replaces the open vault with a backup. The core verifies the master password and the
    /// whole backup before it erases anything; on success the vault is locked and the
    /// restored one opens with the backup's secret.
    func replaceFromBackup(currentPassword: String, url: URL, secret: ImportSecret) async -> String? {
        guard let handle = unlockedHandle, !isWorking else { return Self.busyMessage }
        isWorking = true
        defer { isWorking = false }
        imageCache.removeAll()
        stopPlayback()
        do {
            try await Task.detached(priority: .userInitiated) {
                try handle.replaceFromBackup(currentPassword: currentPassword, path: url.path, secret: secret)
            }.value
        } catch {
            if !Self.vaultExists(at: root) {
                finishErase()
            } else if handle.isLocked() {
                lock()
            }
            // Anything before the erase leaves the vault untouched and open.
            return Self.replaceMessage(for: error)
        }
        // The quick-unlock slots of the old vault are gone; the owner holds the backup's recovery key.
        biometricStore.deleteKey()
        pinStore.deleteKey()
        resetBiometricFailures()
        SnapshotCleaner.removeSnapshots()
        cancelInactivityTimer()
        defaults.set(true, forKey: Self.recoveryConfirmedKey)
        duressEnabled = false
        biometricEnabled = false
        pinEnabled = false
        lockNotice = Self.restoreNotice
        state = .locked
        return nil
    }

    /// Restores a backup into the empty vault directory of a fresh install.
    func restoreBackup(from url: URL, secret: ImportSecret) async -> String? {
        guard case .noVault = state, !isWorking else { return Self.busyMessage }
        isWorking = true
        defer { isWorking = false }
        let root = root
        do {
            try Self.prepareRoot(root)
            _ = try await Task.detached(priority: .userInitiated) {
                try vaultImportFrom(root: root.path, exportPath: url.path, secret: secret)
            }.value
            // The owner already holds a recovery key of this vault; do not force a new one.
            defaults.set(true, forKey: Self.recoveryConfirmedKey)
            lockNotice = Self.duressResetNotice
            state = .locked
            return nil
        } catch {
            return Self.backupMessage(for: error)
        }
    }

    // MARK: Helpers

    func noteImportCancelledByLock() {
        lockNotice = String(localized: "Import cancelled because the vault was locked.")
    }

    private func open(_ handle: VaultHandle) {
        lockNotice = nil
        throttle.reset()
        state = .unlocked(handle)
        refreshHandleState()
        noteActivity()
    }

    /// Reads the duress and Face ID state from the open vault.
    private func refreshHandleState() {
        duressEnabled = unlockedHandle?.isDuressEnabled() ?? false
        isReadOnly = unlockedHandle?.isReadOnly() ?? false
        refreshBiometricState()
        refreshPinState()
    }

    /// Like `refreshBiometricState` for the PIN.
    private func refreshPinState() {
        let hasKey = pinStore.hasKey
        let hasSlot = vaultIsPinEnabled(root: root.path)
        if hasKey != hasSlot {
            pinStore.deleteKey()
            try? vaultRemovePin(root: root.path)
        }
        pinEnabled = hasKey && hasSlot
        let corePaused = vaultIsPinPaused(root: root.path)
        if pinEnabled, pinStore.isPaused != corePaused {
            // Half paused (e.g. the app was killed mid-attempt): pause both sides.
            pinStore.pause()
            try? vaultPausePin(root: root.path)
        }
        pinPaused = pinEnabled && (pinStore.isPaused || vaultIsPinPaused(root: root.path))
    }

    /// Keychain and core slot together; the core slot alone would already block the PIN.
    private func pausePin() {
        guard pinEnabled else { return }
        pinStore.pause()
        try? vaultPausePin(root: root.path)
        refreshPinState()
    }

    /// After a password or recovery unlock; the core has already reactivated its slot.
    private func resumePin() {
        pinStore.resume()
        refreshPinState()
    }

    /// Face ID counts as enabled only if the keychain item and the core slot both exist;
    /// a leftover on one side is removed.
    private func refreshBiometricState() {
        let hasKey = biometricStore.hasKey
        let hasSlot = vaultIsBiometricEnabled(root: root.path)
        if hasKey != hasSlot {
            biometricStore.deleteKey()
            try? vaultRemoveBiometric(root: root.path)
        }
        biometricEnabled = hasKey && hasSlot
    }

    private func cancelInactivityTimer() {
        inactivityTask?.cancel()
        inactivityTask = nil
        lastActivity = nil
    }

    /// Creates the vault directory with complete file protection; also tightens an existing one.
    nonisolated static func prepareRoot(_ root: URL) throws {
        let fm = FileManager.default
        let attributes: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
        if !fm.fileExists(atPath: root.path) {
            try fm.createDirectory(
                at: root, withIntermediateDirectories: true, attributes: attributes)
        }
        try fm.setAttributes(attributes, ofItemAtPath: root.path)
    }

    private static var busyMessage: String { String(localized: "Please wait before trying again.") }

    /// Shown after every restore or import: the core always turns duress off.
    nonisolated static var duressResetNotice: String {
        String(localized: "The panic password was turned off. Set it up again in Security if you need it.")
    }

    private static var restoreNotice: String {
        String(localized: "Backup restored. Unlock with the password the backup had.") + " " + duressResetNotice
    }

    /// Messages for replacing the vault; the core reports a wrong master password and a
    /// wrong backup password alike.
    nonisolated static func replaceMessage(for error: Error) -> String {
        guard let error = error as? ZeError else { return message(for: error) }
        return switch error {
        case .WrongPassword:
            String(localized: "Wrong master password or backup password.")
        default:
            backupMessage(for: error)
        }
    }

    /// Messages for export and import errors.
    nonisolated static func backupMessage(for error: Error) -> String {
        guard let error = error as? ZeError else { return message(for: error) }
        return switch error {
        case .WrongPassword:
            String(localized: "The password does not match this backup.")
        case .WrongRecoveryKey:
            String(localized: "The recovery key does not match this backup.")
        case .DifferentVault:
            String(localized: "This backup is from another vault. You can only restore it in place of this vault.")
        case .ExportFormat, .ExportConflict:
            String(localized: "The backup file is damaged or was changed.")
        case .ReadOnly, .Locked:
            String(localized: "The vault is locked or read-only.")
        default:
            message(for: error)
        }
    }

    nonisolated static func message(for error: Error) -> String {
        guard let error = error as? ZeError else {
            return String(localized: "Something went wrong. Try again.")
        }
        return switch error {
        case .RecoveryKeyFormat, .RecoveryKeyChecksum, .WrongRecoveryKey:
            String(localized: "This recovery key is not valid. Check it for typing mistakes.")
        case .HeaderTampered, .HeaderFormat, .Corrupt, .JournalCorrupt, .RollbackDetected,
            .NotAVault:
            String(localized: "The vault could not be verified. Its data may be damaged or changed.")
        case .Io, .Exists:
            String(localized: "The vault could not be read or written.")
        case .BiometricExpired:
            biometricExpiredMessage
        case .PinExpired:
            pinExpiredMessage
        case .PinInvalid:
            wrongPinMessage
        case .EmptyPassword:
            String(localized: "Enter a password.")
        case .WrongPassword:
            String(localized: "Wrong master password.")
        case .DuressEqualsPassword:
            String(localized: "The panic password must differ from your master password.")
        default:
            String(localized: "Something went wrong. Try again.")
        }
    }
}

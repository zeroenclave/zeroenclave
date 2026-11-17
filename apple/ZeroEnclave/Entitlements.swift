import Foundation
import Observation
import StoreKit

/// Features that can sit behind the premium purchase.
enum Feature: CaseIterable {
    case duressPassword, biometricUnlock, albums, backupExport, bulkExport, multipleVaults, intruderAlert, themes,
        sync, trashRestore
}

/// One way to obtain premium; `Entitlements` unlocks a feature if any source grants it.
protocol EntitlementSource {
    func grants(_ feature: Feature) -> Bool
}

/// Early Bird trial: premium for six months from the App Store download, once per Apple ID.
/// The window comes from Apple's signed `AppTransaction` (production only), so a reinstall or a
/// new device does not restart it. TestFlight and Xcode builds have no meaningful download date;
/// there the window starts when the user activates the trial. The activation and the latest
/// date seen live in the keychain, so a reinstall, edited defaults or a device date set back
/// do not restart or revive the trial.
struct PreReleaseSource: EntitlementSource {
    /// Legacy flag from builds with lifetime Early Bird; migrated to a start date.
    nonisolated static let defaultsKey = "preReleasePremium"
    nonisolated static let startKey = "preReleasePremiumStart"
    nonisolated static let trialDays = 183

    let defaults: UserDefaults
    let store: TrialStore
    var now: () -> Date = { Date() }

    /// Device time, never earlier than the latest time seen before (device date set back).
    var effectiveNow: Date {
        let current = now()
        guard let seen = store.date(.lastSeen), seen > current else {
            store.recordLastSeen(current)
            return current
        }
        return seen
    }

    /// When the user activated the trial; nil if never. The keychain copy survives a reinstall.
    var start: Date? {
        if let date = store.date(.start) { return date }
        let legacy =
            (defaults.object(forKey: Self.startKey) as? Double).map(Date.init(timeIntervalSince1970:))
            // Testers of the lifetime builds get six months from this update.
            ?? (defaults.bool(forKey: Self.defaultsKey) ? effectiveNow : nil)
        if let legacy { store.set(legacy, for: .start) }
        return legacy
    }

    /// First App Store download of this Apple ID, verified by Apple; nil outside the App Store.
    var downloadDate: Date? { store.date(.download) }

    var expiry: Date? {
        guard let from = downloadDate ?? start else { return nil }
        return Calendar.current.date(byAdding: .day, value: Self.trialDays, to: from) ?? from
    }

    var isActive: Bool {
        guard start != nil, let expiry else { return false }
        return effectiveNow < expiry
    }

    /// The window is over (activated or not); it cannot be started again.
    var isExpired: Bool {
        guard let expiry, start != nil || downloadDate != nil else { return false }
        return effectiveNow >= expiry
    }

    func activate() {
        guard start == nil, !isExpired else { return }
        let date = effectiveNow
        store.set(date, for: .start)
        defaults.set(date.timeIntervalSince1970, forKey: Self.startKey)
        defaults.set(true, forKey: Self.defaultsKey)
    }

    func grants(_ feature: Feature) -> Bool { isActive }

    /// Loads the signed download date. Only the production App Store counts; the result is
    /// kept in the keychain so it is known at the next launch before StoreKit answers.
    static func loadDownloadDate(into store: TrialStore) async {
        guard case .verified(let app) = try? await AppTransaction.shared,
            app.environment == .production
        else { return }
        store.set(app.originalPurchaseDate, for: .download)
    }
}

enum TrialStoreKey: String {
    case start, download, lastSeen
}

/// Dates for the Early Bird trial that must survive a reinstall and must not be editable
/// through app defaults or an iOS backup.
protocol TrialStore: AnyObject {
    func date(_ key: TrialStoreKey) -> Date?
    func set(_ date: Date, for key: TrialStoreKey)
}

extension TrialStore {
    /// Moves `lastSeen` forward; writes at most once a minute.
    func recordLastSeen(_ current: Date) {
        if let seen = date(.lastSeen), current.timeIntervalSince(seen) < 60 { return }
        set(current, for: .lastSeen)
    }
}

/// Keychain-backed store: this device only, not in iOS backups, kept across reinstalls.
final class KeychainTrialStore: TrialStore, @unchecked Sendable {
    nonisolated static let defaultService = "com.zeroenclave.app.trial"

    private let service: String
    private let lock = NSLock()
    private var cache: [TrialStoreKey: Date] = [:]

    init(service: String = KeychainTrialStore.defaultService) {
        self.service = service
    }

    func date(_ key: TrialStoreKey) -> Date? {
        lock.withLock {
            if let cached = cache[key] { return cached }
            var result: CFTypeRef?
            let query = base(key).merging([
                kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
            ]) { $1 }
            guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
                let data = result as? Data, data.count == 8
            else { return nil }
            let date = Date(timeIntervalSince1970: data.withUnsafeBytes { $0.loadUnaligned(as: Double.self) })
            cache[key] = date
            return date
        }
    }

    func set(_ date: Date, for key: TrialStoreKey) {
        lock.withLock {
            var value = date.timeIntervalSince1970
            let data = Data(bytes: &value, count: 8)
            let update = [kSecValueData as String: data]
            if SecItemUpdate(base(key) as CFDictionary, update as CFDictionary) == errSecItemNotFound {
                let add = base(key).merging([
                    kSecValueData as String: data,
                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                ]) { $1 }
                SecItemAdd(add as CFDictionary, nil)
            }
            cache[key] = date
        }
    }

    private func base(_ key: TrialStoreKey) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
        ]
    }
}

/// In-memory store for tests and previews.
final class MemoryTrialStore: TrialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [TrialStoreKey: Date] = [:]

    func date(_ key: TrialStoreKey) -> Date? { lock.withLock { values[key] } }
    func set(_ date: Date, for key: TrialStoreKey) { lock.withLock { values[key] = date } }
}

/// StoreKit 2 placeholder for the one-time purchase. Not wired to any purchase flow yet:
/// `grants` stays false until `refresh()` finds a purchase or an early-adopter record.
final class StoreSource: EntitlementSource {
    nonisolated static let productID = "com.zeroenclave.app.premium"
    /// TODO: set to the release date; installs first purchased before it keep premium.
    nonisolated static let earlyAdopterCutoff: Date? = nil

    private(set) var hasPremium = false

    func grants(_ feature: Feature) -> Bool { hasPremium }

    /// TODO: call at launch and on `Transaction.updates` once the product exists.
    func refresh() async {
        let purchased = await Self.hasPremiumTransaction()
        hasPremium = purchased ? true : await Self.isEarlyAdopter()
    }

    /// True if `Transaction.currentEntitlements` holds a verified, non-revoked premium purchase.
    static func hasPremiumTransaction() async -> Bool {
        for await result in Transaction.currentEntitlements {
            if case .verified(let transaction) = result,
                transaction.productID == productID, transaction.revocationDate == nil
            {
                return true
            }
        }
        return false
    }

    /// TODO: early-adopter hook. True if the app was first obtained before `earlyAdopterCutoff`
    /// (`AppTransaction.originalPurchaseDate`); false while no cutoff is set.
    static func isEarlyAdopter() async -> Bool {
        guard let cutoff = earlyAdopterCutoff,
            case .verified(let app) = try? await AppTransaction.shared
        else { return false }
        return app.originalPurchaseDate < cutoff
    }
}

/// Single place that decides which features are available.
@Observable
final class Entitlements {
    @ObservationIgnored private let preRelease: PreReleaseSource
    @ObservationIgnored private let trialStore: TrialStore
    @ObservationIgnored private let sources: [EntitlementSource]
    /// Bumped on every change so views re-read the sources.
    private var revision = 0

    init(
        defaults: UserDefaults = .standard, trialStore: TrialStore = KeychainTrialStore(),
        extraSources: [EntitlementSource] = [StoreSource()], now: @escaping () -> Date = { Date() }
    ) {
        self.trialStore = trialStore
        preRelease = PreReleaseSource(defaults: defaults, store: trialStore, now: now)
        sources = [preRelease] + extraSources
    }

    func isUnlocked(_ feature: Feature) -> Bool {
        _ = revision
        return sources.contains { $0.grants(feature) }
    }

    /// Premium is one purchase: albums stand for every premium feature (Enclave Link is separate).
    var hasPremium: Bool { isUnlocked(.albums) }

    /// Whether the Early Bird trial is running.
    var preReleaseActive: Bool {
        _ = revision
        return preRelease.isActive
    }

    /// End of the Early Bird trial; nil before activation.
    var preReleaseExpiry: Date? {
        _ = revision
        return preRelease.expiry
    }

    /// The trial ran out; it cannot be started again.
    var preReleaseExpired: Bool {
        _ = revision
        return preRelease.isExpired
    }

    /// Starts the six-month trial; does nothing if it was started before.
    func activatePreRelease() {
        preRelease.activate()
        revision += 1
    }

    /// Re-reads the sources, e.g. after the app defaults were reset.
    func reload() { revision += 1 }

    /// Fetches the signed App Store download date that bounds the Early Bird window.
    func refreshDownloadDate() async {
        await PreReleaseSource.loadDownloadDate(into: trialStore)
        revision += 1
    }
}

/// View-model of the "Premium required" sheet: runs an action only for unlocked features.
@Observable
final class PremiumGate {
    var isPresentingRequired = false
    /// The feature that asked for premium; the sheet highlights it.
    var requested: Feature?

    func require(_ feature: Feature) {
        requested = feature
        isPresentingRequired = true
    }

    /// Runs `action` if `feature` is unlocked; otherwise presents the sheet. Returns whether it ran.
    @discardableResult
    func perform(_ feature: Feature, entitlements: Entitlements, action: () -> Void) -> Bool {
        guard entitlements.isUnlocked(feature) else {
            require(feature)
            return false
        }
        action()
        return true
    }
}

#if DEBUG
    extension PreReleaseSource {
        /// Debug builds only: `-ZEResetTrial` clears the trial so the free state can be tested
        /// on a device. Not compiled into release builds.
        static func resetIfRequested(defaults: UserDefaults = .standard) {
            guard ProcessInfo.processInfo.arguments.contains("-ZEResetTrial") else { return }
            SecItemDelete(
                [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: KeychainTrialStore.defaultService,
                ] as CFDictionary)
            defaults.removeObject(forKey: startKey)
            defaults.removeObject(forKey: defaultsKey)
        }
    }
#endif

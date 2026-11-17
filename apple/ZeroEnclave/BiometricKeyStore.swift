import Foundation
import LocalAuthentication
import Security

enum BiometricKeyError: Error, Equatable {
    case unavailable
    /// The system or the app dismissed the Face ID prompt.
    case cancelled
    /// The user dismissed the prompt; counts as a failed attempt (usually follows a non-match).
    case userCancelled
    /// The face did not match (or biometrics are locked out after repeated mismatches).
    case mismatch
    /// iOS locked biometrics after too many attempts; the device passcode re-enables them.
    case lockout
    /// No face is enrolled on this device.
    case notEnrolled
    /// The Secure Enclave key or its ciphertext is gone (e.g. a new face was enrolled).
    case invalidated
    case failed
}

/// State of the biometric hardware as reported by the system.
enum BiometricAvailability: Equatable, Sendable {
    case available, lockedOut, notEnrolled, unavailable
}

/// Holds the device-bound `bio_key`, encrypted by a Secure Enclave key (crypto §12).
/// Abstracted so tests can run without a Secure Enclave.
protocol BiometricKeyStore: Sendable {
    /// True if the key material exists in the keychain.
    var hasKey: Bool { get }
    /// True if biometrics can be used on this device.
    var isAvailable: Bool { get }
    /// Detailed state from `canEvaluatePolicy`; no prompt is shown.
    var availability: BiometricAvailability { get }
    /// Replaces any existing key and returns a fresh 32-byte `bio_key`; the caller wipes it.
    func createKey() throws -> Data
    /// Returns the `bio_key` after the biometric prompt; the caller wipes it.
    func loadKey(reason: String) throws -> Data
    /// Deletes the Secure Enclave key and the keychain item.
    func deleteKey()
}

extension Data {
    /// Overwrites the bytes in place.
    mutating func wipe() { resetBytes(in: 0..<count) }
}

/// Real implementation: P-256 key in the Secure Enclave guarded by `.biometryCurrentSet`
/// (no passcode fallback), ECIES ciphertext in a this-device-only keychain item.
struct SecureEnclaveKeyStore: BiometricKeyStore {
    nonisolated static let identifier = "com.zeroenclave.app.biometric"
    private static let tag = Data(identifier.utf8)
    private static let account = "bio-key"

    private var itemQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.identifier,
            kSecAttrAccount as String: Self.account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private var keyQuery: [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Self.tag,
        ]
    }

    var hasKey: Bool {
        var query = itemQuery
        query[kSecReturnAttributes as String] = true
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    var isAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    var availability: BiometricAvailability {
        var error: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return .available
        }
        switch (error?.code).flatMap(LAError.Code.init(rawValue:)) {
        case .biometryLockout: return .lockedOut
        case .biometryNotEnrolled: return .notEnrolled
        default: return .unavailable
        }
    }

    func createKey() throws -> Data {
        guard isAvailable else { throw BiometricKeyError.unavailable }
        deleteKey()
        var cfError: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet], &cfError)
        else { throw BiometricKeyError.failed }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Self.tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else { throw BiometricKeyError.failed }

        var bytes = [UInt8](repeating: 0, count: 32)
        defer { bytes.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess,
            let ciphertext = SecKeyCreateEncryptedData(
                publicKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
                Data(bytes) as CFData, &cfError) as Data?
        else {
            deleteKey()
            throw BiometricKeyError.failed
        }

        var item = itemQuery
        item[kSecValueData as String] = ciphertext
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        item[kSecAttrSynchronizable as String] = false
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
            deleteKey()
            throw BiometricKeyError.failed
        }
        return Data(bytes)
    }

    func loadKey(reason: String) throws -> Data {
        var itemRequest = itemQuery
        itemRequest[kSecReturnData as String] = true
        var ciphertextRef: CFTypeRef?
        guard SecItemCopyMatching(itemRequest as CFDictionary, &ciphertextRef) == errSecSuccess,
            let ciphertext = ciphertextRef as? Data
        else { throw BiometricKeyError.invalidated }

        let context = LAContext()
        context.localizedReason = reason
        // An empty title hides the "Enter Password" fallback.
        context.localizedFallbackTitle = ""
        var keyRequest = keyQuery
        keyRequest[kSecReturnRef as String] = true
        keyRequest[kSecUseAuthenticationContext as String] = context
        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(keyRequest as CFDictionary, &keyRef)
        guard status == errSecSuccess, let keyRef else {
            throw Self.classify(status)
        }
        let privateKey = keyRef as! SecKey
        var cfError: Unmanaged<CFError>?
        guard
            let plain = SecKeyCreateDecryptedData(
                privateKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
                ciphertext as CFData, &cfError) as Data?
        else {
            let code = (cfError?.takeRetainedValue()).map { CFErrorGetCode($0) } ?? 0
            throw Self.classify(OSStatus(code))
        }
        guard plain.count == 32 else { throw BiometricKeyError.invalidated }
        return plain
    }

    func deleteKey() {
        SecItemDelete(itemQuery as CFDictionary)
        SecItemDelete(keyQuery as CFDictionary)
    }

    private static func classify(_ status: OSStatus) -> BiometricKeyError {
        switch status {
        case errSecItemNotFound: .invalidated
        case OSStatus(LAError.biometryLockout.rawValue): .lockout
        case OSStatus(LAError.biometryNotEnrolled.rawValue): .notEnrolled
        case OSStatus(LAError.biometryNotAvailable.rawValue): .unavailable
        case errSecAuthFailed, OSStatus(LAError.authenticationFailed.rawValue): .mismatch
        case errSecUserCanceled, OSStatus(LAError.userCancel.rawValue): .userCancelled
        case OSStatus(LAError.systemCancel.rawValue), OSStatus(LAError.appCancel.rawValue): .cancelled
        // The app was not in the foreground yet (e.g. the prompt raced the launch): retryable.
        case errSecInteractionNotAllowed, OSStatus(LAError.notInteractive.rawValue): .cancelled
        default: .failed
        }
    }
}

/// Persistent count of failed Face ID evaluations; survives app restarts.
protocol BiometricFailureCounter: Sendable {
    /// Failed attempts since the last successful unlock.
    var count: Int { get }
    /// Adds one failure and returns the new count.
    @discardableResult func recordFailure() -> Int
    /// Deletes the stored counter.
    func reset()
}

/// Keychain-backed counter: this-device-only, not synced, never in UserDefaults.
struct KeychainBiometricFailureCounter: BiometricFailureCounter {
    nonisolated static let identifier = "com.zeroenclave.app.biometric-failures"
    private static let account = "failures"

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.identifier,
            kSecAttrAccount as String: Self.account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    var count: Int {
        var request = query
        request[kSecReturnData as String] = true
        var ref: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &ref)
        if status == errSecItemNotFound { return 0 }
        // Fail closed: an unreadable or malformed counter blocks Face ID.
        guard status == errSecSuccess, let data = ref as? Data,
            let text = String(data: data, encoding: .utf8), let value = Int(text), value >= 0
        else { return Int.max }
        return value
    }

    @discardableResult
    func recordFailure() -> Int {
        let current = count
        guard current < Int.max else { return current }
        let next = current + 1
        let data = Data(String(next).utf8)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            item[kSecAttrSynchronizable as String] = false
            SecItemAdd(item as CFDictionary, nil)
        }
        return next
    }

    func reset() {
        SecItemDelete(query as CFDictionary)
    }
}

/// Kernel boot time and wall clock in Unix seconds, as the core expects them.
enum SystemClock {
    static func bootTime() -> UInt64 {
        var mib = [CTL_KERN, KERN_BOOTTIME]
        var value = timeval()
        var size = MemoryLayout<timeval>.stride
        guard sysctl(&mib, 2, &value, &size, nil, 0) == 0, value.tv_sec > 0 else { return 0 }
        return UInt64(value.tv_sec)
    }

    static func now() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970))
    }
}

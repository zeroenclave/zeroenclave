import Foundation
import LocalAuthentication
import Security

enum PinKeyError: Error, Equatable {
    case unavailable
    /// The Secure Enclave rejected the PIN.
    case wrongPin
    /// The key or its ciphertext is gone, or PIN unlock is paused.
    case invalidated
    case failed
}

/// Holds the device-bound `se_secret` for PIN unlock (crypto §12), encrypted by a Secure
/// Enclave key that only works with the PIN as application password.
/// Abstracted so tests can run without a Secure Enclave.
protocol PinKeyStore: Sendable {
    /// True if the key material exists in the keychain, active or paused.
    var hasKey: Bool { get }
    /// True if PIN unlock waits for the master password.
    var isPaused: Bool { get }
    /// Replaces any existing key and returns a fresh 32-byte `se_secret`; the caller wipes it.
    func createKey(pin: String) throws -> Data
    /// Returns the `se_secret` for this PIN; the caller wipes it. One attempt: the ciphertext is
    /// paused before decrypting and made active again only if the Secure Enclave accepts the PIN.
    func loadKey(pin: String) throws -> Data
    /// Pauses PIN unlock until `resume`, e.g. on a manual lock.
    func pause()
    /// After a password or recovery unlock: the same PIN works again.
    func resume()
    /// Deletes the Secure Enclave key and the keychain items.
    func deleteKey()
}

/// Real implementation: P-256 Secure Enclave key with `.applicationPassword` (the PIN),
/// ECIES ciphertext in a this-device-only keychain item.
struct SecureEnclavePinStore: PinKeyStore {
    nonisolated static let identifier = "com.zeroenclave.app.pin"
    private static let tag = Data(identifier.utf8)
    private static let account = "se-secret"
    /// Same ciphertext while PIN unlock is paused.
    private static let pausedAccount = "se-secret-paused"

    private var itemQuery: [String: Any] { query(account: Self.account) }
    private var pausedQuery: [String: Any] { query(account: Self.pausedAccount) }

    private func query(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.identifier,
            kSecAttrAccount as String: account,
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

    var hasKey: Bool { exists(itemQuery) || exists(pausedQuery) }

    var isPaused: Bool { !exists(itemQuery) && exists(pausedQuery) }

    private func exists(_ base: [String: Any]) -> Bool {
        var query = base
        query[kSecReturnAttributes as String] = true
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    private func read(_ base: [String: Any]) -> Data? {
        var query = base
        query[kSecReturnData as String] = true
        var ref: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &ref) == errSecSuccess else { return nil }
        return ref as? Data
    }

    /// Copies the ciphertext to `to`, then deletes `from`; the copy comes first so it is never lost.
    @discardableResult
    private func move(from: [String: Any], to: [String: Any]) -> Bool {
        guard let data = read(from) else { return false }
        SecItemDelete(to as CFDictionary)
        guard store(data, in: to) else { return false }
        return SecItemDelete(from as CFDictionary) == errSecSuccess
    }

    func pause() { move(from: itemQuery, to: pausedQuery) }

    func resume() { move(from: pausedQuery, to: itemQuery) }

    /// Context that hands the PIN to the Secure Enclave without any system UI.
    private static func context(pin: String) -> LAContext {
        let context = LAContext()
        context.interactionNotAllowed = true
        context.setCredential(Data(pin.utf8), type: .applicationPassword)
        return context
    }

    func createKey(pin: String) throws -> Data {
        deleteKey()
        var cfError: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [.privateKeyUsage, .applicationPassword], &cfError)
        else { throw PinKeyError.failed }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseAuthenticationContext as String: Self.context(pin: pin),
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Self.tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError),
            let publicKey = SecKeyCopyPublicKey(privateKey)
        else { throw PinKeyError.unavailable }

        var bytes = [UInt8](repeating: 0, count: 32)
        defer { bytes.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess,
            let ciphertext = SecKeyCreateEncryptedData(
                publicKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
                Data(bytes) as CFData, &cfError) as Data?,
            storeCiphertext(ciphertext)
        else {
            deleteKey()
            throw PinKeyError.failed
        }
        return Data(bytes)
    }

    func loadKey(pin: String) throws -> Data {
        guard let ciphertext = read(itemQuery) else { throw PinKeyError.invalidated }
        // Use up the attempt first: killing the app from here on leaves PIN unlock paused.
        guard move(from: itemQuery, to: pausedQuery) else { throw PinKeyError.failed }

        var keyRequest = keyQuery
        keyRequest[kSecReturnRef as String] = true
        keyRequest[kSecUseAuthenticationContext as String] = Self.context(pin: pin)
        var keyRef: CFTypeRef?
        guard SecItemCopyMatching(keyRequest as CFDictionary, &keyRef) == errSecSuccess, let keyRef else {
            throw PinKeyError.invalidated
        }
        let privateKey = keyRef as! SecKey
        var cfError: Unmanaged<CFError>?
        guard
            let plain = SecKeyCreateDecryptedData(
                privateKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
                ciphertext as CFData, &cfError) as Data?,
            plain.count == 32
        else { throw PinKeyError.wrongPin }
        guard move(from: pausedQuery, to: itemQuery) else { throw PinKeyError.failed }
        return plain
    }

    func deleteKey() {
        SecItemDelete(itemQuery as CFDictionary)
        SecItemDelete(pausedQuery as CFDictionary)
        SecItemDelete(keyQuery as CFDictionary)
    }

    private func storeCiphertext(_ ciphertext: Data) -> Bool {
        store(ciphertext, in: itemQuery)
    }

    private func store(_ ciphertext: Data, in base: [String: Any]) -> Bool {
        var item = base
        item[kSecValueData as String] = ciphertext
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        item[kSecAttrSynchronizable as String] = false
        return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
    }
}

/// The six digits of an unlock PIN.
enum UnlockPin {
    static let length = 6

    static func sanitized(_ text: String) -> String {
        String(text.filter(\.isASCII).filter(\.isNumber).prefix(length))
    }

    static func isValid(_ pin: String) -> Bool {
        pin.count == length && sanitized(pin) == pin
    }
}

import CryptoKit
import Foundation
import Security

/// Keychain-backed vault key.
///
/// One generic-password item holds a random 256-bit key. It is created on first
/// launch with:
/// - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — unreadable while the
///   device is locked, never migrated to a new device, never synced to iCloud
///   Keychain;
/// - `kSecAttrSynchronizable = false`.
///
/// If the vault file exists but the key item is gone (for example after a
/// Keychain reset), `loadKey()` returns nil and `EncryptedVault` refuses to
/// continue: it never creates a replacement key, because that would look like a
/// successful load of empty state.
final class KeychainVaultKeyStore: VaultKeyProviding {

    static let defaultService = "dev.veil.messenger.vault"
    static let defaultAccount = "vault-encryption-key-v1"

    private let service: String
    private let account: String

    init(service: String = KeychainVaultKeyStore.defaultService,
         account: String = KeychainVaultKeyStore.defaultAccount) {
        self.service = service
        self.account = account
    }

    // MARK: - VaultKeyProviding

    func loadKey() throws -> SymmetricKey? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else {
                throw VeilStorageError.keyUnavailable("елемент Keychain має неочікуваний розмір")
            }
            return SymmetricKey(data: data)
        case errSecItemNotFound:
            return nil
        default:
            throw VeilStorageError.keyUnavailable(Self.describe(status))
        }
    }

    func createKey() throws -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }

        var attributes = baseQuery()
        attributes[kSecValueData as String] = keyData
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecAttrSynchronizable as String] = false

        let status = SecItemAdd(attributes as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return key
        case errSecDuplicateItem:
            // Another instance won the race; use whatever is stored now.
            guard let existing = try loadKey() else {
                throw VeilStorageError.keyCreationFailed("конфлікт створення ключа")
            }
            return existing
        default:
            throw VeilStorageError.keyCreationFailed(Self.describe(status))
        }
    }

    // MARK: - Private

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        query[kSecAttrSynchronizable as String] = false
        return query
    }

    /// Maps the most relevant OSStatus values to short, user-facing reasons.
    /// The raw status is included because it is not sensitive and makes
    /// diagnostics on a real device possible without logging data.
    private static func describe(_ status: OSStatus) -> String {
        let reason: String
        switch status {
        case errSecNotAvailable:
            reason = "Keychain недоступний"
        case errSecAuthFailed:
            reason = "автентифікація Keychain не пройдена"
        case errSecInteractionNotAllowed:
            reason = "пристрій заблокований"
        case errSecMissingEntitlement:
            reason = "немає entitlement для Keychain"
        case errSecDecode:
            reason = "елемент Keychain не декодується"
        default:
            reason = "помилка Keychain"
        }
        return "\(reason), код \(status)"
    }
}

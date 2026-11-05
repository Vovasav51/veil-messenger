import CryptoKit
import Foundation

// MARK: - Storage errors

enum VeilStorageError: LocalizedError, Equatable {
    case vaultKeyLost
    case keyUnavailable(String)
    case keyCreationFailed(String)
    case vaultCorrupted(String)
    case readFailed(String)
    case writeFailed(String)

    var errorDescription: String? {
        switch self {
        case .vaultKeyLost:
            return "Файл сховища існує, але ключ шифрування в Keychain відсутній. Дані не видалено; відновлення без ключа неможливе."
        case .keyUnavailable(let detail):
            return "Keychain недоступний: \(detail). Сховище не відкрито."
        case .keyCreationFailed(let detail):
            return "Не вдалося створити ключ шифрування у Keychain: \(detail)."
        case .vaultCorrupted(let detail):
            return "Сховище пошкоджене (\(detail)). Файл збережено для діагностики, нова ідентичність не створюється."
        case .readFailed(let detail):
            return "Не вдалося прочитати сховище: \(detail)."
        case .writeFailed(let detail):
            return "Не вдалося зберегти сховище: \(detail). Зміни не застосовано."
        }
    }
}

// MARK: - Dependencies (injectable for tests)

protocol VaultKeyProviding {
    /// Returns nil only when no key has been created yet. A missing key with an
    /// existing vault file is fatal (see `VeilStorageError.vaultKeyLost`).
    func loadKey() throws -> SymmetricKey?
    func createKey() throws -> SymmetricKey
}

protocol VaultFileStoring {
    /// Returns nil when nothing has been persisted yet.
    func readEncryptedData() throws -> Data?
    func writeEncryptedData(_ data: Data) throws
}

/// Bridge that lets `EncryptedVault` persist the Signal protocol state that the
/// live `SignalService` owns.
///
/// Why a bridge instead of writing `vault.state.crypto` directly from the
/// service: the coordinator mutates `vault.state` through an `inout` parameter
/// while calling into the service. Touching the same stored property from the
/// service would be an overlapping-access trap under Swift exclusivity
/// enforcement. The service therefore keeps the working `CryptoState` and the
/// vault copies it in at commit time (and restores it on rollback).
@MainActor
protocol CryptoStateMirroring: AnyObject {
    var mirroredCryptoState: CryptoState { get }
    func restoreMirroredCryptoState(_ state: CryptoState)
}

// MARK: - EncryptedVault

/// AES-GCM encrypted, atomically written vault at
/// `Application Support/Veil/vault.bin`.
///
/// Properties:
/// - 256-bit key created with `SymmetricKey(size: .bits256)` and stored in the
///   Keychain as `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
///   `kSecAttrSynchronizable = false`. No plaintext key file or key-export UI;
///   the generic-password key is readable into app memory (not Secure Enclave).
/// - File is written with `.completeFileProtection` and excluded from backups.
/// - The GCM additional authenticated data is the fixed header, so a truncated,
///   swapped or hand-crafted blob fails authentication instead of decoding.
/// - A corrupt or unreadable file throws; the vault never resets itself and
///   never falls back to a plaintext file.
///
/// Transactions snapshot the whole value state (including `crypto`), and restore
/// it if the body or the commit fails.
@MainActor
final class EncryptedVault {

    var state: VaultState

    /// Set by `SignalService.init`. Only used at commit/rollback time.
    weak var cryptoMirror: CryptoStateMirroring?

    private let key: SymmetricKey
    private let fileStore: VaultFileStoring

    /// `VaultState` as last durably written. Used to skip redundant writes so a
    /// coordinator that calls `save()` and then lets `transaction` commit does
    /// not double-write.
    private var persistedState: VaultState?
    private var transactionDepth = 0

    init(fileStore: VaultFileStoring? = nil, keyStore: VaultKeyProviding? = nil) throws {
        let resolvedFileStore: VaultFileStoring
        if let fileStore {
            resolvedFileStore = fileStore
        } else {
            resolvedFileStore = try FileVaultStore()
        }
        let resolvedKeyStore: VaultKeyProviding = keyStore ?? KeychainVaultKeyStore()

        self.fileStore = resolvedFileStore

        if let blob = try resolvedFileStore.readEncryptedData() {
            guard let key = try resolvedKeyStore.loadKey() else {
                throw VeilStorageError.vaultKeyLost
            }
            self.key = key
            let opened = try EncryptedVault.open(blob, key: key)
            self.state = opened
            self.persistedState = opened
        } else {
            self.key = try resolvedKeyStore.loadKey() ?? resolvedKeyStore.createKey()
            self.state = VaultState()
            self.persistedState = nil
        }
    }

    // MARK: - Persistence

    /// Persists the current state immediately when called outside a
    /// transaction. Inside a transaction the write is deferred to the commit so
    /// that a later failure rolls the whole change set back (and so the
    /// coordinator's `inout` access to `state` is not overlapped).
    func save() throws {
        guard transactionDepth == 0 else {
            // Deferred: `transaction` performs the single atomic write after the
            // body returns, so a later failure leaves disk untouched.
            return
        }
        try persistCurrentState()
    }

    /// Runs `body` as one atomic unit. On any error the full state — contacts,
    /// messages, outbox, processed ids and the Signal protocol state — is
    /// restored and nothing is written.
    func transaction<T>(_ body: () throws -> T) throws -> T {
        // Adopt any crypto state the service produced outside a transaction so
        // the snapshot below is the real baseline for a rollback.
        if let cryptoMirror {
            state.crypto = cryptoMirror.mirroredCryptoState
        }

        let snapshot = state
        let mirrorSnapshot = cryptoMirror?.mirroredCryptoState
        let persistedSnapshot = persistedState

        transactionDepth += 1
        defer { transactionDepth -= 1 }

        do {
            let result = try body()
            if transactionDepth == 1 {
                try persistCurrentState()
            }
            return result
        } catch {
            state = snapshot
            if let mirrorSnapshot {
                cryptoMirror?.restoreMirroredCryptoState(mirrorSnapshot)
            }
            if transactionDepth == 1 {
                // Nothing was written during the transaction (writes are
                // deferred and atomic), so the durable marker is unchanged.
                persistedState = persistedSnapshot
            }
            throw error
        }
    }

    /// True when there are uncommitted in-memory changes.
    var hasUnsavedChanges: Bool {
        guard let persistedState else { return state != VaultState() }
        return persistedState != state || (cryptoMirror.map { $0.mirroredCryptoState != state.crypto } ?? false)
    }

    private func persistCurrentState() throws {
        var snapshot = state
        if let cryptoMirror {
            snapshot.crypto = cryptoMirror.mirroredCryptoState
            state.crypto = snapshot.crypto
        }

        if let persistedState, persistedState == snapshot {
            return
        }

        let payload: Data
        do {
            payload = try JSONEncoder().encode(snapshot)
        } catch {
            throw VeilStorageError.writeFailed("серіалізація стану")
        }

        let blob = try EncryptedVault.seal(payload, key: key)
        do {
            try fileStore.writeEncryptedData(blob)
        } catch let error as VeilStorageError {
            throw error
        } catch {
            throw VeilStorageError.writeFailed("запис файлу")
        }

        persistedState = snapshot
    }

    // MARK: - Sealed box

    private static let magic = Data("VEILVLT1".utf8)
    private static let formatVersion: UInt8 = 1
    private static let header: Data = {
        var header = magic
        header.append(formatVersion)
        return header
    }()
    private static let headerLength = 9

    private static func seal(_ plaintext: Data, key: SymmetricKey) throws -> Data {
        do {
            let box = try AES.GCM.seal(plaintext, using: key, authenticating: header)
            guard let combined = box.combined else {
                throw VeilStorageError.writeFailed("порожній GCM-бокс")
            }
            var blob = header
            blob.append(combined)
            return blob
        } catch let error as VeilStorageError {
            throw error
        } catch {
            throw VeilStorageError.writeFailed("шифрування AES-GCM")
        }
    }

    private static func open(_ blob: Data, key: SymmetricKey) throws -> VaultState {
        guard blob.count >= headerLength + 28 else {
            throw VeilStorageError.vaultCorrupted("файл закороткий")
        }
        guard blob.prefix(headerLength) == header else {
            throw VeilStorageError.vaultCorrupted("невідомий формат файлу")
        }

        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: blob.dropFirst(headerLength))
            plaintext = try AES.GCM.open(box, using: key, authenticating: header)
        } catch {
            // Wrong key or modified bytes; both are fatal and never "recovered"
            // by starting over.
            throw VeilStorageError.vaultCorrupted("не вдалося перевірити автентичність AES-GCM")
        }

        do {
            return try JSONDecoder().decode(VaultState.self, from: plaintext)
        } catch {
            throw VeilStorageError.vaultCorrupted("структура стану не читається")
        }
    }
}

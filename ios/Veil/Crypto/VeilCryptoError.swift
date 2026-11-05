import Foundation
import LibSignalClient

// MARK: - Errors
//
// All messages are user-facing Ukrainian text: the UI shows
// `localizedDescription` directly. No error ever embeds key material,
// ciphertext or a raw libsignal payload; only field names and short reasons.

enum VeilCryptoError: LocalizedError, Equatable {
    /// No identity in the vault yet (first launch before onboarding).
    case notProvisioned
    /// Identity/registration id existed but could not be read.
    case corruptedState(String)
    case identityMissing
    case idSpaceExhausted
    /// The remote identity does not match the pinned contact identity.
    case identityMismatch(String)
    /// libsignal refused the identity as untrusted.
    case untrustedIdentity(String)
    /// No session and no prekey bundle supplied.
    case missingBundle
    case messageTooLarge(Int)
    case unsupportedMessageType(UInt8)
    case invalidEnvelope(String)
    case invalidBundleField(String)
    case invalidCiphertext
    case notUTF8Plaintext
    case sessionNotFound
    case duplicateMessage
    case decryptionFailed(String)
    case provisioningFailed(String)

    var errorDescription: String? {
        switch self {
        case .notProvisioned:
            return "Локальна ідентичність ще не створена. Завершіть реєстрацію."
        case .corruptedState(let detail):
            return "Стан Signal у сховищі пошкоджений (\(detail)). Ключі не перегенеровано, щоб не втратити ідентичність."
        case .identityMissing:
            return "Ключ ідентичності відсутній у сховищі. Потрібна діагностика, а не нова ідентичність."
        case .idSpaceExhausted:
            return "Вичерпано простір ідентифікаторів передключів. Потрібна перевірка стану сховища."
        case .identityMismatch(let detail):
            return "Ключ ідентичності не збігається: \(detail). Шифрування/розшифрування скасовано."
        case .untrustedIdentity(let detail):
            return "Signal відхилив невідомий або змінений ключ співрозмовника (\(detail)). Потрібне ручне підтвердження."
        case .missingBundle:
            return "Немає сесії з цим контактом і немає бандла передключів. Оновіть контакт і повторіть."
        case .messageTooLarge(let bytes):
            return "Повідомлення завелике: \(bytes) байтів UTF-8, максимум 4096."
        case .unsupportedMessageType(let type):
            return "Неочікуваний тип Signal-повідомлення (\(type))."
        case .invalidEnvelope(let detail):
            return "Некоректний конверт повідомлення: \(detail)."
        case .invalidBundleField(let field):
            return "Некоректне поле бандла передключів: \(field)."
        case .invalidCiphertext:
            return "Шифротекст пошкоджений або не є коректним base64."
        case .notUTF8Plaintext:
            return "Розшифровані дані не є текстом UTF-8."
        case .sessionNotFound:
            return "Немає активної сесії для цього відправника. Перше повідомлення має бути prekey-повідомленням."
        case .duplicateMessage:
            return "Повідомлення вже було розшифровано раніше (повтор)."
        case .decryptionFailed(let detail):
            return "Не вдалося розшифрувати повідомлення: \(detail)."
        case .provisioningFailed(let detail):
            return "Не вдалося створити локальні ключі: \(detail)."
        }
    }

    /// Maps a libsignal error onto a user-readable Veil error without leaking
    /// message contents. Unmapped errors are reported generically.
    static func map(_ error: Error) -> VeilCryptoError {
        if let error = error as? VeilCryptoError { return error }

        guard let signalError = error as? SignalError else {
            return .decryptionFailed("внутрішня помилка протоколу")
        }

        switch signalError {
        case .untrustedIdentity(let message):
            return .untrustedIdentity(shortReason(message))
        case .duplicatedMessage(_):
            return .duplicateMessage
        case .sessionNotFound(_):
            return .sessionNotFound
        case .invalidMessage(let message):
            return .decryptionFailed(shortReason(message))
        case .invalidSignature(let message):
            return .decryptionFailed("невірний підпис (\(shortReason(message)))")
        case .invalidKey(let message):
            return .decryptionFailed("некоректний ключ (\(shortReason(message)))")
        case .invalidKeyIdentifier(let message):
            return .decryptionFailed("невідомий ідентифікатор ключа (\(shortReason(message)))")
        case .unrecognizedMessageVersion(let message):
            return .decryptionFailed("невідома версія повідомлення (\(shortReason(message)))")
        case .invalidSession(let message):
            return .decryptionFailed("некоректний стан сесії (\(shortReason(message)))")
        case .invalidState(let message):
            return .corruptedState(shortReason(message))
        case .invalidArgument(let message):
            return .decryptionFailed("некоректний аргумент (\(shortReason(message)))")
        case .verificationFailed(let message):
            return .decryptionFailed("перевірка не пройдена (\(shortReason(message)))")
        default:
            return .decryptionFailed("помилка протоколу Signal")
        }
    }

    /// libsignal detail strings are already short, but they can contain the
    /// protocol address. Keep only the first clause and cap the length so the
    /// UI stays readable.
    private static func shortReason(_ message: String) -> String {
        let firstLine = message.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: true).first
        let collapsed = (firstLine.map(String.init) ?? message)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return String(collapsed.prefix(120))
    }
}

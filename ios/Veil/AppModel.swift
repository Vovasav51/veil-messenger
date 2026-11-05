import Combine
import Foundation
import Security

// MARK: - Model value types

/// Identity generated *before* registration so a failed network call can be
/// retried with the same uid instead of minting a new account identity.
/// The uid itself is not a secret; it lives in the Keychain because the shared
/// `VaultState` has no field for a pre-account record.
struct PendingRegistration: Codable, Equatable {
    var uid: String
    var handle: String
    var serverURL: String
}

/// Result of an exact directory lookup, shown to the user before the contact is
/// added so the safety fingerprint can be compared out of band.
struct ContactDraft: Identifiable {
    let uid: String
    let handle: String
    let identityKey: String
    let fingerprint: String

    var id: String { uid }
}

struct ChatSummary: Identifiable {
    let peerUID: String
    let contact: Contact?
    let displayHandle: String
    let lastText: String
    let lastDate: Date
    let lastOutgoing: Bool

    var id: String { peerUID }
}

// MARK: - Input / coordinator errors

enum AppFailure: LocalizedError, Equatable {
    case notReady
    case noAccount
    case unknownContact
    case emptyMessage
    case messageTooLong
    case invalidHandle
    case selfContact
    case handleInUse(String)
    case identityMismatch(String)
    case invalidRegistrationResponse(String)
    case unsupportedMessageType(UInt8)
    case busy

    var errorDescription: String? {
        switch self {
        case .notReady:
            return "Сховище ще не готове."
        case .noAccount:
            return "Спочатку завершіть реєстрацію."
        case .unknownContact:
            return "Контакт не знайдено."
        case .emptyMessage:
            return "Порожнє повідомлення."
        case .messageTooLong:
            return "Повідомлення перевищує 4096 байтів UTF-8."
        case .invalidHandle:
            return "Нікнейм: 3–24 символи, лише a–z, 0–9 та _."
        case .selfContact:
            return "Це ваш власний нікнейм."
        case .handleInUse(let uid):
            return "Нікнейм уже прив'язаний до іншого uid (\(uid.prefix(8))…)."
        case .identityMismatch(let detail):
            return detail
        case .invalidRegistrationResponse(let detail):
            return "Сервер повернув неузгоджену відповідь реєстрації (\(detail)). Акаунт не збережено; повторна спроба використає той самий uid."
        case .unsupportedMessageType(let type):
            return "Неочікуваний тип Signal-повідомлення (\(type))."
        case .busy:
            return "Інша операція ще виконується."
        }
    }
}

// MARK: - App model

/// Single `@MainActor` coordinator that owns the vault, the Signal service and
/// the relay client. All state transitions happen on the main actor; exactly one
/// synchronous vault transaction can be in flight at a time.
@MainActor
final class AppModel: ObservableObject {

    // MARK: Presentation types

    enum SyncPhase: Equatable {
        case idle
        case syncing
        case paused
        case retry(seconds: Int)
        case failed(String)
    }

    enum Busy: Equatable {
        case none
        case registering
        case lookingUp
        case sending
    }

    struct Banner: Identifiable {
        enum Kind { case info, success, warning, error }
        let id = UUID()
        let kind: Kind
        let text: String
    }

    // MARK: Published state

    /// Snapshot of the persisted vault state; refreshed after every transaction.
    @Published private(set) var vaultState = VaultState()
    @Published private(set) var bootstrapFailure: String?
    @Published private(set) var syncPhase: SyncPhase = .idle
    @Published private(set) var lastSyncAt: Date?
    @Published private(set) var banner: Banner?
    @Published private(set) var busy: Busy = .none
    @Published private(set) var pendingRegistration: PendingRegistration?
    @Published private(set) var canRetryWithNewUID = false
    @Published private(set) var undecryptableCount = 0
    @Published private(set) var rejectedOutboxCount = 0

    // MARK: Private state

    private let vault: EncryptedVault?
    private let signal: SignalService?
    private var relay: RelayClient?

    private var pollTask: Task<Void, Never>?
    private var pollGeneration = 0
    private var isActive = false
    private var isSyncing = false
    private var isFlushing = false
    private var inTransaction = false

    private var rejectedOutboxIDs: Set<String> = []
    private var decryptAttempts: [String: Int] = [:]
    private var undecryptableIDs: Set<String> = []

    private let maxDecryptAttempts = 5

    // MARK: Lifecycle

    init() {
        var loadedVault: EncryptedVault?
        var loadedSignal: SignalService?
        var loadedFailure: String?

        do {
            let vault = try EncryptedVault()
            if vault.state.account != nil {
                guard vault.state.crypto.hasIdentity,
                      !vault.state.crypto.signedPreKeys.isEmpty,
                      !vault.state.crypto.kyberPreKeys.isEmpty else {
                    throw VeilStorageError.vaultCorrupted("акаунт існує, але приватні ключі протоколу відсутні")
                }
            }
            loadedVault = vault
            loadedSignal = SignalService(vault: vault)
        } catch {
            loadedFailure = "Не вдалося відкрити зашифроване сховище. Локальні дані не видалено. Перезапуск не допоможе — потрібна діагностика, а не скидання."
        }

        self.vault = loadedVault
        self.signal = loadedSignal
        self.bootstrapFailure = loadedFailure
        self.pendingRegistration = PendingRegistrationStore.load()

        guard let loadedVault else { return }
        self.vaultState = loadedVault.state

        if let account = loadedVault.state.account {
            if let url = try? RelayClient.validateServerURL(account.serverURL) {
                self.relay = RelayClient(baseURL: url, token: account.token)
            } else {
                self.banner = Banner(kind: .error, text: "Збережена адреса релея некоректна або не HTTPS. Мережеві операції вимкнено.")
            }
        }
    }

    // MARK: Derived accessors

    var account: Account? { vaultState.account }
    var isBootstrapped: Bool { bootstrapFailure == nil && vault != nil }

    var contacts: [Contact] {
        vaultState.contacts.sorted { $0.handle.localizedCaseInsensitiveCompare($1.handle) == .orderedAscending }
    }

    func contact(for uid: String) -> Contact? {
        vaultState.contacts.first { $0.uid == uid }
    }

    func displayHandle(for uid: String) -> String {
        contact(for: uid)?.handle ?? "uid:\(uid.prefix(8))"
    }

    func messages(for peerUID: String) -> [ChatMessage] {
        vaultState.messages
            .filter { $0.peerUID == peerUID }
            .sorted { lhs, rhs in
                lhs.createdAt == rhs.createdAt ? lhs.id < rhs.id : lhs.createdAt < rhs.createdAt
            }
    }

    var chatSummaries: [ChatSummary] {
        var latest: [String: ChatMessage] = [:]
        for message in vaultState.messages {
            if let current = latest[message.peerUID] {
                if message.createdAt >= current.createdAt { latest[message.peerUID] = message }
            } else {
                latest[message.peerUID] = message
            }
        }
        return latest.compactMap { peerUID, message in
            let contact = contact(for: peerUID)
            return ChatSummary(
                peerUID: peerUID,
                contact: contact,
                displayHandle: contact?.handle ?? "uid:\(peerUID.prefix(8))",
                lastText: message.text,
                lastDate: message.createdAt,
                lastOutgoing: message.outgoing
            )
        }
        .sorted { $0.lastDate > $1.lastDate }
    }

    var contactsWithoutChat: [Contact] {
        let peers = Set(vaultState.messages.map(\.peerUID))
        return contacts.filter { !peers.contains($0.uid) }
    }

    // MARK: Vault access

    /// Single write path. The closure runs synchronously inside
    /// `EncryptedVault.transaction`; `save()` is called inside the body (it is
    /// deferred to the transaction commit) so a commit failure rolls the whole
    /// mutation back. The vault itself is passed in, not an `inout` view of
    /// `state`, so a crypto call inside the body can never overlap exclusive
    /// access to `vault.state`.
    @discardableResult
    private func write<T>(_ body: (EncryptedVault) throws -> T) throws -> T {
        guard let vault else { throw AppFailure.notReady }
        precondition(!inTransaction, "Nested vault transactions are not allowed")
        inTransaction = true
        defer { inTransaction = false }

        let result = try vault.transaction { () throws -> T in
            let value = try body(vault)
            try vault.save()
            return value
        }
        refresh()
        return result
    }

    private func refresh() {
        if let vault { vaultState = vault.state }
    }

    // MARK: Active state / polling

    func setActive(_ active: Bool) {
        guard active != isActive else { return }
        isActive = active
        if active {
            startPollingIfPossible()
        } else {
            stopPolling()
        }
    }

    private func startPollingIfPossible() {
        guard isActive, vaultState.account != nil, pollTask == nil else { return }
        pollGeneration += 1
        let generation = pollGeneration
        pollTask = Task { [weak self] in
            await self?.pollLoop(generation: generation)
        }
    }

    private func stopPolling() {
        pollGeneration += 1
        pollTask?.cancel()
        pollTask = nil
        if vaultState.account != nil, syncPhase != .paused {
            syncPhase = .paused
        }
    }

    /// Foreground-only loop: poll, back off on failure, respect cancellation,
    /// never run two cycles at once.
    private func pollLoop(generation: Int) async {
        var failures = 0

        while !Task.isCancelled, generation == pollGeneration {
            do {
                try await runSyncCycle()
                failures = 0
                lastSyncAt = Date()
                syncPhase = .idle
                try await Task.sleep(nanoseconds: 3_000_000_000)
            } catch is CancellationError {
                break
            } catch let error as RelayError where error.isAuthFailure {
                syncPhase = .failed(error.localizedDescription)
                present(error)
                break
            } catch {
                failures += 1
                let seconds = min(3 << min(failures - 1, 4), 40)
                syncPhase = .retry(seconds: seconds)
                if failures == 1 || failures % 5 == 0 {
                    present(error)
                }
                do {
                    try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
                } catch {
                    break
                }
            }
        }

        if pollGeneration == generation {
            pollTask = nil
        }
        if Task.isCancelled, vaultState.account != nil {
            syncPhase = .paused
        }
    }

    /// Manual refresh (pull-to-refresh, settings button). Overlapping calls are
    /// harmlessly coalesced by the `isSyncing` guard.
    func syncNow() async {
        guard vaultState.account != nil else { return }
        do {
            try await runSyncCycle()
            lastSyncAt = Date()
            syncPhase = .idle
        } catch is CancellationError {
            return
        } catch let error as RelayError where error.isAuthFailure {
            syncPhase = .failed(error.localizedDescription)
            present(error)
        } catch {
            present(error)
            if syncPhase != .paused { syncPhase = .retry(seconds: 5) }
        }
    }

    func syncIfNeeded() async {
        guard vaultState.account != nil else { return }
        if let lastSyncAt, Date().timeIntervalSince(lastSyncAt) < 8 { return }
        await syncNow()
    }

    private func runSyncCycle() async throws {
        guard !isSyncing else { return }
        isSyncing = true
        defer { isSyncing = false }

        syncPhase = .syncing
        guard vaultState.account != nil else { return }
        guard relay != nil else { throw RelayError.notConfigured }

        try await flushOutboxOnce()
        try Task.checkCancellation()
        try await pollInbox()
    }

    // MARK: Registration

    func register(serverURLText: String, handleText: String, forceNewUID: Bool = false) async {
        guard busy == .none else { return }
        guard let signal else {
            report(.error, "Сховище недоступне.")
            return
        }

        busy = .registering
        canRetryWithNewUID = false
        defer { busy = .none }

        let baseURL: URL
        let handle: String
        do {
            baseURL = try RelayClient.validateServerURL(serverURLText)
            handle = try VeilHandle.normalize(handleText)
        } catch {
            present(error)
            return
        }

        // Durable pre-network identity record: uid + target server.
        let previous = PendingRegistrationStore.load()
        var uid: String
        if !forceNewUID, let previous, previous.serverURL == baseURL.absoluteString {
            uid = previous.uid
        } else {
            uid = makeUUIDv7()
        }

        do {
            try PendingRegistrationStore.save(
                PendingRegistration(uid: uid, handle: handle, serverURL: baseURL.absoluteString)
            )
        } catch {
            report(.error, "Не вдалося зберегти незавершену реєстрацію в Keychain. Реєстрацію скасовано, щоб не створити акаунт без можливості повторити.")
            return
        }
        pendingRegistration = PendingRegistration(uid: uid, handle: handle, serverURL: baseURL.absoluteString)

        do {
            // Local identity keys become durable before any network call.
            let bundle = try write { _ in try signal.publicBundle() }
            let client = RelayClient(baseURL: baseURL, token: nil)
            let response = try await client.register(uid: uid, handle: handle, bundle: bundle)

            // The response is untrusted input: it must describe exactly the
            // account we asked for, otherwise a hostile/broken relay could get
            // us to store someone else's uid/handle or a bogus token.
            guard response.uid == uid else {
                throw AppFailure.invalidRegistrationResponse("uid не збігається з надісланим")
            }
            guard response.handle == handle else {
                throw AppFailure.invalidRegistrationResponse("нікнейм не збігається з надісланим")
            }
            let token = response.token
            let tokenIsSane = (16...512).contains(token.count)
                && token.unicodeScalars.allSatisfy { scalar in
                    !CharacterSet.whitespacesAndNewlines.contains(scalar)
                        && !CharacterSet.controlCharacters.contains(scalar)
                }
            guard tokenIsSane else {
                throw AppFailure.invalidRegistrationResponse("токен відсутній або має неприпустимий формат")
            }

            let account = Account(
                uid: uid,
                handle: handle,
                token: token,
                serverURL: baseURL.absoluteString
            )
            try write { vault in vault.state.account = account }

            PendingRegistrationStore.clear()
            pendingRegistration = nil
            relay = RelayClient(baseURL: baseURL, token: account.token)
            report(.success, "Акаунт @\(account.handle) створено. Відбиток безпеки — у Налаштуваннях.")
            startPollingIfPossible()
        } catch let error as RelayError {
            handleRegistrationFailure(error)
        } catch {
            present(error)
        }
    }

    private func handleRegistrationFailure(_ error: RelayError) {
        present(error)

        if case .server(let status, let detail) = error {
            if status == 409 {
                let lowered = detail.lowercased()
                if lowered.contains("uid") {
                    canRetryWithNewUID = true
                    report(
                        .warning,
                        "Сервер уже має акаунт із цим uid, а токен недоступний. Відновлення акаунта не підтримується. Можна зареєструвати новий uid з тією самою локальною ідентичністю."
                    )
                } else {
                    report(.warning, "Цей нікнейм уже зайнятий. Виберіть інший — uid і ключі залишаться тими самими.")
                }
                return
            }
        }

        if error.isUncertain {
            report(
                .warning,
                "Результат реєстрації невідомий: запит міг дійти до сервера. Повторіть спробу — буде використано той самий uid і ту саму локальну ідентичність."
            )
        }
    }

    func retryRegistrationWithNewUID(serverURLText: String, handleText: String) async {
        await register(serverURLText: serverURLText, handleText: handleText, forceNewUID: true)
    }

    // MARK: Contacts

    func lookupContact(handleText: String) async throws -> ContactDraft {
        guard let signal else { throw AppFailure.notReady }
        guard let relay, let account = vaultState.account else { throw AppFailure.noAccount }
        guard busy == .none else { throw AppFailure.busy }

        busy = .lookingUp
        defer { busy = .none }

        let handle = try VeilHandle.normalize(handleText)
        guard handle != account.handle else { throw AppFailure.selfContact }

        // Directory only. The prekey bundle is fetched — and checked against this
        // identity, the pin and the directory — at the first send, so merely
        // opening the compose screen never consumes a one-time prekey.
        let entry = try await relay.directory(handle: handle)
        guard entry.deviceID == 1 else {
            throw AppFailure.identityMismatch("Каталог повернув неочікуваний device_id (\(entry.deviceID)). Контакт не додано.")
        }
        guard !entry.identityKey.isEmpty else {
            throw AppFailure.identityMismatch("Каталог повернув порожній ключ ідентичності. Контакт не додано.")
        }
        if let existing = contact(for: entry.uid),
           !existing.identityKey.isEmpty,
           existing.identityKey != entry.identityKey {
            throw AppFailure.identityMismatch("Каталог повертає інший ключ ідентичності для вже доданого контакту @\(existing.handle). Додавання скасовано.")
        }

        let draftContact = Contact(uid: entry.uid, handle: entry.handle, identityKey: entry.identityKey, verified: false)
        let fingerprint = try write { _ in try signal.fingerprint(for: draftContact, localUID: account.uid) }

        return ContactDraft(
            uid: entry.uid,
            handle: entry.handle,
            identityKey: entry.identityKey,
            fingerprint: fingerprint
        )
    }

    func addContact(_ draft: ContactDraft, verified: Bool) throws {
        guard let account = vaultState.account else { throw AppFailure.noAccount }
        guard let signal else { throw AppFailure.notReady }
        guard draft.uid != account.uid else { throw AppFailure.selfContact }

        try write { vault in
            try signal.pinContact(Contact(uid: draft.uid, handle: draft.handle, identityKey: draft.identityKey, verified: verified))
            if let index = vault.state.contacts.firstIndex(where: { $0.uid == draft.uid }) {
                let existing = vault.state.contacts[index]
                // A pinned key must never be replaced by a new draft, and a
                // verification flag must never be upgraded for an identity the
                // user did not actually compare. An empty pin (TOFU placeholder)
                // may be filled once.
                guard existing.identityKey.isEmpty || existing.identityKey == draft.identityKey else {
                    throw AppFailure.identityMismatch(
                        "Ключ ідентичності контакту @\(existing.handle) відрізняється від перевіреного зараз. Оновлення й підтвердження скасовано."
                    )
                }
                vault.state.contacts[index] = Contact(
                    uid: existing.uid,
                    handle: draft.handle,
                    identityKey: existing.identityKey.isEmpty ? draft.identityKey : existing.identityKey,
                    verified: existing.verified || verified
                )
            } else if let clash = vault.state.contacts.first(where: { $0.handle == draft.handle && $0.uid != draft.uid }) {
                throw AppFailure.handleInUse(clash.uid)
            } else {
                vault.state.contacts.append(
                    Contact(uid: draft.uid, handle: draft.handle, identityKey: draft.identityKey, verified: verified)
                )
            }
        }

        report(.success, "Контакт @\(draft.handle) додано. Відбиток підтверджуйте лише після порівняння поза застосунком.")
    }

    func setVerified(_ verified: Bool, for uid: String) throws {
        try write { vault in
            guard let index = vault.state.contacts.firstIndex(where: { $0.uid == uid }) else {
                throw AppFailure.unknownContact
            }
            let contact = vault.state.contacts[index]
            vault.state.contacts[index] = Contact(
                uid: contact.uid,
                handle: contact.handle,
                identityKey: contact.identityKey,
                verified: verified
            )
        }
    }

    func fingerprint(for contact: Contact) throws -> String {
        guard let signal, let account = vaultState.account else { throw AppFailure.noAccount }
        return try write { _ in try signal.fingerprint(for: contact, localUID: account.uid) }
    }

    func ownFingerprint() throws -> String {
        guard let signal, let account = vaultState.account else { throw AppFailure.noAccount }
        let bundle = try write { _ in try signal.publicBundle() }
        let selfContact = Contact(uid: account.uid, handle: account.handle, identityKey: bundle.identityKey, verified: true)
        return try write { _ in try signal.fingerprint(for: selfContact, localUID: account.uid) }
    }

    // MARK: Sending

    /// Encrypt + persist the message and its outbox entry in one transaction,
    /// then hand the exact ciphertext to the relay. A later retry of the same
    /// outbox entry reuses the stored id and ciphertext (no re-ratcheting).
    func send(text: String, to contact: Contact) async throws {
        guard let signal, let account = vaultState.account else { throw AppFailure.noAccount }
        guard busy == .none else { throw AppFailure.busy }

        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw AppFailure.emptyMessage }
        guard trimmed.utf8.count <= 4096 else { throw AppFailure.messageTooLong }

        busy = .sending
        defer { busy = .none }

        let needsSession = !hasPriorTraffic(with: contact.uid)
        var bootstrapBundle: PublicBundle?
        if needsSession {
            bootstrapBundle = try await verifiedBundle(for: contact)
        }

        do {
            try commitOutgoing(text: trimmed, to: contact, bundle: bootstrapBundle, account: account, signal: signal)
        } catch let error as VeilCryptoError {
            // Only "no session yet" is recoverable with a freshly fetched bundle.
            // Identity/pin failures must surface unchanged.
            switch error {
            case .missingBundle, .sessionNotFound:
                guard bootstrapBundle == nil else { throw error }
                let fresh = try await verifiedBundle(for: contact)
                try commitOutgoing(text: trimmed, to: contact, bundle: fresh, account: account, signal: signal)
            default:
                throw error
            }
        }

        await flushOutbox()
    }

    private func hasPriorTraffic(with peerUID: String) -> Bool {
        vaultState.messages.contains { $0.peerUID == peerUID }
            || vaultState.outbox.contains { $0.recipientUID == peerUID }
    }

    /// Directory and prekey bundle identities must agree, and must match the
    /// pinned contact identity, before the first encryption to that contact.
    private func verifiedBundle(for contact: Contact) async throws -> PublicBundle {
        guard let relay else { throw RelayError.notConfigured }

        let entry = try await relay.directory(handle: contact.handle)
        guard entry.uid == contact.uid else {
            throw AppFailure.identityMismatch("Каталог повернув інший uid для @\(contact.handle). Шифрування скасовано.")
        }
        guard entry.identityKey == contact.identityKey else {
            throw AppFailure.identityMismatch("Ключ ідентичності в каталозі змінився. Шифрування скасовано — перевірте контакт вручну.")
        }

        let bundle = try await relay.prekeys(uid: contact.uid)
        guard bundle.identityKey == entry.identityKey, bundle.identityKey == contact.identityKey else {
            throw AppFailure.identityMismatch("Ключ ідентичності в бандлі передключів не збігається з каталогом або піном. Шифрування скасовано.")
        }
        guard bundle.deviceId == entry.deviceID else {
            throw AppFailure.identityMismatch("device_id у бандлі не збігається з каталогом. Шифрування скасовано.")
        }
        guard (1...16380).contains(bundle.registrationId) else {
            throw AppFailure.identityMismatch("Некоректний registration_id у бандлі. Шифрування скасовано.")
        }
        return bundle
    }

    private func commitOutgoing(
        text: String,
        to contact: Contact,
        bundle: PublicBundle?,
        account: Account,
        signal: SignalService
    ) throws {
        let messageID = makeUUIDv7()
        let createdAt = Date()

        try write { vault in
            let (messageType, ciphertext) = try signal.encrypt(
                text: text,
                to: contact,
                bundle: bundle,
                localUID: account.uid
            )
            guard messageType == 2 || messageType == 3 else {
                throw AppFailure.unsupportedMessageType(messageType)
            }
            guard !ciphertext.isEmpty else {
                throw AppFailure.identityMismatch("Шифрування повернуло порожній шифротекст. Повідомлення не збережено.")
            }

            vault.state.outbox.append(
                OutgoingEnvelope(
                    id: messageID,
                    recipientUID: contact.uid,
                    recipientDeviceId: 1,
                    messageType: messageType,
                    ciphertext: ciphertext
                )
            )
            vault.state.messages.append(
                ChatMessage(
                    id: messageID,
                    peerUID: contact.uid,
                    text: text,
                    outgoing: true,
                    createdAt: createdAt,
                    status: "queued"
                )
            )
        }
    }

    // MARK: Outbox

    /// Manual flush used after enqueueing. Errors are surfaced, not thrown.
    func flushOutbox() async {
        do {
            try await flushOutboxOnce()
        } catch is CancellationError {
            return
        } catch {
            present(error)
        }
    }

    /// Sends queued envelopes oldest-first. Status changes and outbox removals
    /// are persisted only after the relay accepted the exact stored ciphertext.
    private func flushOutboxOnce() async throws {
        guard let relay, vaultState.account != nil else { throw AppFailure.noAccount }
        guard !isFlushing else { return }
        isFlushing = true
        defer { isFlushing = false }

        let pending = vaultState.outbox

        for envelope in pending {
            try Task.checkCancellation()
            if rejectedOutboxIDs.contains(envelope.id) { continue }

            do {
                try await relay.send(envelope)
            } catch let error as RelayError where error.isPermanentRejection {
                rejectedOutboxIDs.insert(envelope.id)
                rejectedOutboxCount = rejectedOutboxIDs.count
                report(.error, "Повідомлення відхилено сервером: \(error.localizedDescription)")
                continue
            }

            try write { vault in
                vault.state.outbox.removeAll { $0.id == envelope.id }
                if let index = vault.state.messages.firstIndex(where: { $0.id == envelope.id }) {
                    let message = vault.state.messages[index]
                    vault.state.messages[index] = ChatMessage(
                        id: message.id,
                        peerUID: message.peerUID,
                        text: message.text,
                        outgoing: message.outgoing,
                        createdAt: message.createdAt,
                        status: "sent"
                    )
                }
            }
            _ = rejectedOutboxIDs.remove(envelope.id)
            rejectedOutboxCount = rejectedOutboxIDs.count
        }
    }

    // MARK: Receiving

    /// Fetches the mailbox and commits each message in its own transaction
    /// (ratchet + chat message + dedup id). Only committed (or previously
    /// committed) ids are ACKed; decrypt/storage failures are never ACKed.
    private func pollInbox() async throws {
        guard let signal, let relay, let account = vaultState.account else { return }

        let envelopes = try await relay.fetchMessages()
        guard !envelopes.isEmpty else { return }

        var committed: [String] = []
        var processed = Set(vaultState.processedEnvelopeIDs)
        var failures = 0

        for envelope in envelopes {
            try Task.checkCancellation()

            // Routing fields are untrusted; only our own inbox is processed.
            guard envelope.recipientDeviceId == 1,
                  envelope.recipientUID.lowercased() == account.uid.lowercased()
            else { continue }

            if processed.contains(envelope.id) {
                // Already durably committed in an earlier pull: ACK without decrypting.
                committed.append(envelope.id)
                continue
            }

            if undecryptableIDs.contains(envelope.id) { continue }

            let createdAt = envelope.createdAt > 1_000_000
                ? Date(timeIntervalSince1970: envelope.createdAt)
                : Date()

            do {
                try write { vault in
                    // A contact may have been verified before the first inbound
                    // message. Its directory key must constrain Signal TOFU too.
                    if let contact = vault.state.contacts.first(where: { $0.uid.lowercased() == envelope.senderUID.lowercased() }) {
                        try signal.pinContact(contact)
                    }
                    let text = try signal.decrypt(envelope, localUID: account.uid)
                    if !vault.state.processedEnvelopeIDs.contains(envelope.id) {
                        vault.state.messages.append(
                            ChatMessage(
                                id: envelope.id,
                                peerUID: envelope.senderUID,
                                text: text,
                                outgoing: false,
                                createdAt: createdAt,
                                status: "received"
                            )
                        )
                        vault.state.processedEnvelopeIDs.append(envelope.id)
                    }
                }
                processed.insert(envelope.id)
                committed.append(envelope.id)
                decryptAttempts[envelope.id] = nil
                _ = undecryptableIDs.remove(envelope.id)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                failures += 1
                let attempts = (decryptAttempts[envelope.id] ?? 0) + 1
                decryptAttempts[envelope.id] = attempts
                if attempts >= maxDecryptAttempts {
                    // Never ACK: the server keeps the ciphertext, but we stop
                    // burning cycles on it and tell the user.
                    undecryptableIDs.insert(envelope.id)
                }
            }
            undecryptableCount = undecryptableIDs.count
        }

        undecryptableCount = undecryptableIDs.count

        if failures > 0 {
            report(
                .warning,
                "Не вдалося розшифрувати \(failures) повідомлень. Їх не підтверджено серверу; спробуємо ще раз пізніше."
            )
        }

        if !committed.isEmpty {
            do {
                try await relay.acknowledge(ids: committed)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                // Envelopes stay in the mailbox; dedup guarantees no duplicates.
                present(error)
            }
        }
    }

    // MARK: Diagnostics

    func checkHealth() async {
        guard let relay else {
            report(.error, RelayError.notConfigured.localizedDescription)
            return
        }
        do {
            let health = try await relay.health()
            report(.success, "Реле доступне. Версія API: \(health.version).")
        } catch is CancellationError {
            return
        } catch {
            present(error)
        }
    }

    func dismissBanner() {
        banner = nil
    }

    private func present(_ error: Error) {
        if error is CancellationError { return }
        let text = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        banner = Banner(kind: .error, text: text)
    }

    private func report(_ kind: Banner.Kind, _ text: String) {
        banner = Banner(kind: kind, text: text)
    }
}

// MARK: - Handle rules

enum VeilHandle {
    static func normalize(_ raw: String) throws -> String {
        // Reject invisible/non-ASCII characters before Foundation trimming or
        // Unicode case folding could turn them into an apparently valid name.
        guard raw.unicodeScalars.allSatisfy({ $0.isASCII }) else {
            throw AppFailure.invalidHandle
        }
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if value.hasPrefix("@") { value.removeFirst() }

        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789_")
        guard (3...24).contains(value.count),
              !value.isEmpty,
              value.unicodeScalars.allSatisfy({ allowed.contains($0) })
        else { throw AppFailure.invalidHandle }

        return value
    }
}

// MARK: - Pending registration storage

/// Non-secret bookkeeping (uid / handle / server) so an interrupted
/// registration can be retried with the same uid. Kept in the Keychain rather
/// than UserDefaults or a plaintext file.
enum PendingRegistrationStore {
    private static let service = "app.veil.pending-registration"
    private static let accountKey = "pending"

    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: accountKey
        ]
    }

    static func load() -> PendingRegistration? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data
        else { return nil }
        return try? JSONDecoder().decode(PendingRegistration.self, from: data)
    }

    static func save(_ value: PendingRegistration) throws {
        let data = try JSONEncoder().encode(value)

        var attributes = baseQuery
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        attributes[kSecAttrSynchronizable as String] = false

        SecItemDelete(baseQuery as CFDictionary)

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    static func clear() {
        SecItemDelete(baseQuery as CFDictionary)
    }
}

import Foundation

// MARK: - Transport errors

/// Errors surfaced by the relay client. Descriptions are user-facing Ukrainian
/// text; the client never logs request bodies, tokens, ciphertext or keys.
enum RelayError: LocalizedError, Equatable {
    case notConfigured
    case invalidServerURL
    case insecureTransport
    case transport(String)
    case unauthorized
    case rateLimited(String)
    case server(status: Int, detail: String)
    case decoding
    case emptyResponse
    case responseTooLarge
    case unexpectedResponse(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "Немає з'єднання з релеєм."
        case .invalidServerURL:
            return "Некоректна адреса сервера."
        case .insecureTransport:
            return "Дозволено лише HTTPS. HTTP приймається тільки для локальної розробки (127.0.0.1)."
        case .transport(let detail):
            return "Мережева помилка: \(detail)"
        case .unauthorized:
            return "Сервер відхилив токен (401). Повторний вхід без відновлення акаунта неможливий."
        case .rateLimited(let detail):
            return detail.isEmpty ? "Занадто багато запитів (429). Спробуйте пізніше." : "Занадто багато запитів (429): \(detail)"
        case .server(let status, let detail):
            return detail.isEmpty ? "Сервер повернув помилку \(status)." : "Сервер повернув \(status): \(detail)"
        case .decoding:
            return "Неочікувана відповідь сервера."
        case .emptyResponse:
            return "Порожня відповідь сервера."
        case .responseTooLarge:
            return "Відповідь сервера перевищує допустимий розмір. Читання перервано."
        case .unexpectedResponse(let detail):
            return detail.isEmpty ? "Сервер не підтвердив запит." : "Сервер повернув неузгоджену відповідь: \(detail)"
        }
    }

    /// Auth failures must stop the polling loop instead of retrying forever.
    var isAuthFailure: Bool {
        if case .unauthorized = self { return true }
        return false
    }

    /// Rejections that will not succeed on retry (bad payload, conflict, too large).
    var isPermanentRejection: Bool {
        switch self {
        case .server(let status, _):
            return (400..<500).contains(status) && status != 401 && status != 408 && status != 429
        default:
            return false
        }
    }

    /// The request may or may not have reached the server (timeout, connection loss).
    var isUncertain: Bool {
        if case .transport = self { return true }
        return false
    }
}

// MARK: - Relay client

/// Small, first-party client for the Veil relay JSON API v1.
///
/// Design rules enforced here:
/// - HTTPS only; plain HTTP is accepted solely for loopback hosts in DEBUG builds.
/// - Ephemeral URLSession, no URL cache, no cookie storage, no credential storage.
/// - No redirects are followed, so an `Authorization` header can never be
///   replayed to a different origin by a 30x response.
/// - No request/response logging.
final class RelayClient: @unchecked Sendable {

    let baseURL: URL
    private let token: String?
    private let session: URLSession
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    init(baseURL: URL, token: String?) {
        self.baseURL = baseURL
        self.token = token

        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 30
        configuration.httpMaximumConnectionsPerHost = 4
        configuration.waitsForConnectivity = false
        self.session = URLSession(configuration: configuration)
    }

    deinit {
        session.finishTasksAndInvalidate()
    }

    // MARK: URL validation

    /// Normalizes and validates a user-supplied relay URL.
    /// Returns a URL whose path ends with "/" so relative API paths keep any
    /// reverse-proxy prefix (e.g. https://host/veil/).
    static func validateServerURL(_ text: String) throws -> URL {
        var trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw RelayError.invalidServerURL }

        let lowered = trimmed.lowercased()
        if lowered.contains("://"),
           !lowered.hasPrefix("https://"), !lowered.hasPrefix("http://") {
            throw RelayError.insecureTransport
        }
        if !lowered.hasPrefix("https://") && !lowered.hasPrefix("http://") {
            trimmed = "https://" + trimmed
        }

        guard var components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(),
              let host = components.host,
              !host.isEmpty
        else { throw RelayError.invalidServerURL }

        // Credentials in a URL would leak through storage and history.
        guard components.user == nil, components.password == nil else {
            throw RelayError.invalidServerURL
        }

        components.query = nil
        components.fragment = nil

        switch scheme {
        case "https":
            break
        case "http":
            #if DEBUG
            guard isLoopbackHost(host) else { throw RelayError.insecureTransport }
            #else
            throw RelayError.insecureTransport
            #endif
        default:
            throw RelayError.insecureTransport
        }

        if components.path.isEmpty {
            components.path = "/"
        } else if !components.path.hasSuffix("/") {
            components.path += "/"
        }

        guard let url = components.url else { throw RelayError.invalidServerURL }
        return url
    }

    /// Debug-only cleartext policy. Accepted hosts are exactly:
    /// `localhost`, `::1` (with or without brackets) and strict dotted-quad
    /// IPv4 addresses inside 127.0.0.0/8. A name such as `127.attacker.com`
    /// or `localhost.evil.com` is **not** loopback: it would send a bearer token
    /// in cleartext to a remote host.
    static func isLoopbackHost(_ host: String) -> Bool {
        let normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        if normalized == "localhost" { return true }
        if normalized == "::1" || normalized == "[::1]" { return true }

        return isStrictLoopbackIPv4(normalized)
    }

    /// Strict dotted-quad parser: four decimal octets, no signs, no letters,
    /// no leading/trailing junk, value 0...255, first octet exactly 127.
    private static func isStrictLoopbackIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }

        var octets: [UInt8] = []
        octets.reserveCapacity(4)
        for part in parts {
            guard !part.isEmpty, part.count <= 3 else { return false }
            guard part.allSatisfy({ $0.isASCII && $0.isNumber }) else { return false }
            // Reject any multi-digit part with a leading zero: it never appears
            // in a canonical URL host and only exists to confuse parsers.
            guard part.count == 1 || !part.hasPrefix("0") else { return false }
            guard let value = UInt8(part) else { return false }
            octets.append(value)
        }

        return octets[0] == 127
    }

    // MARK: API surface

    func health() async throws -> Health {
        try await perform(try request(path: "health", method: "GET", body: nil, authorized: false), as: Health.self)
    }

    func register(uid: String, handle: String, bundle: PublicBundle) async throws -> RegisterResponse {
        let payload = RegisterBody(uid: uid, handle: handle, deviceID: 1, bundle: bundle)
        let body = try encoder.encode(payload)
        return try await perform(try request(path: "v1/register", method: "POST", body: body, authorized: false), as: RegisterResponse.self)
    }

    func directory(handle: String) async throws -> DirectoryEntry {
        let encodedHandle = handle.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? handle
        return try await perform(try request(path: "v1/directory/\(encodedHandle)", method: "GET", body: nil, authorized: true), as: DirectoryEntry.self)
    }

    func prekeys(uid: String) async throws -> PublicBundle {
        let encodedUID = uid.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? uid
        return try await perform(try request(path: "v1/prekeys/\(encodedUID)", method: "GET", body: nil, authorized: true), as: PublicBundle.self)
    }

    func uploadPrekeys(_ bundle: PublicBundle) async throws {
        let body = try encoder.encode(bundle)
        _ = try await perform(try request(path: "v1/prekeys", method: "PUT", body: body, authorized: true), as: OKResponse.self)
    }

    func send(_ envelope: OutgoingEnvelope) async throws {
        let payload = SendBody(
            id: envelope.id,
            recipientUID: envelope.recipientUID,
            recipientDeviceID: envelope.recipientDeviceId,
            messageType: envelope.messageType,
            ciphertext: envelope.ciphertext
        )
        let body = try encoder.encode(payload)
        let response = try await perform(
            try request(path: "v1/messages", method: "POST", body: body, authorized: true),
            as: SendResponse.self
        )
        // Only an explicit acceptance of *this* message may clear the outbox.
        guard response.accepted else {
            throw RelayError.unexpectedResponse("accept не підтверджено")
        }
        guard response.id == envelope.id else {
            throw RelayError.unexpectedResponse("id відповіді не збігається з надісланим")
        }
    }

    func fetchMessages() async throws -> [Envelope] {
        let response = try await perform(try request(path: "v1/messages", method: "GET", body: nil, authorized: true), as: MessagesResponse.self)
        return response.messages
    }

    func acknowledge(ids: [String]) async throws {
        guard !ids.isEmpty else { return }
        let body = try encoder.encode(AckBody(ids: ids))
        _ = try await perform(try request(path: "v1/messages/ack", method: "POST", body: body, authorized: true), as: OKResponse.self)
    }

    // MARK: Request plumbing

    private func request(path: String, method: String, body: Data?, authorized: Bool) throws -> URLRequest {
        guard let url = URL(string: path, relativeTo: baseURL) else { throw RelayError.invalidServerURL }

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 20
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        if authorized {
            guard let token, !token.isEmpty else { throw RelayError.unauthorized }
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        return request
    }

    /// Hard ceiling for a successful response body. The pull endpoint returns at
    /// most 100 envelopes; SPEC caps ciphertext at 64 KiB, so 100 × 64 KiB of
    /// base64 (~8.6 MiB) plus JSON overhead fits comfortably. Anything larger is
    /// treated as hostile and the stream is abandoned.
    static let maxResponseBytes = 12 * 1024 * 1024
    /// Error bodies only need `{detail}`; keep them tiny.
    private static let maxErrorBytes = 64 * 1024
    /// Cancellation checks are cheap; do not check per byte.
    private static let cancelCheckStride = 16 * 1024

    /// Streams the response instead of buffering it blindly, so a hostile or
    /// misbehaving relay cannot make the app allocate an unbounded body.
    private func perform<T: Decodable>(_ request: URLRequest, as type: T.Type) async throws -> T {
        let pair: (URLSession.AsyncBytes, URLResponse)
        do {
            pair = try await session.bytes(for: request, delegate: NoRedirectTaskDelegate())
        } catch let error as URLError where error.code == .cancelled {
            throw CancellationError()
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw RelayError.transport(Self.sanitize(error.localizedDescription))
        }

        let stream = pair.0
        let response = pair.1

        guard let http = response as? HTTPURLResponse else { throw RelayError.decoding }

        guard (200..<300).contains(http.statusCode) else {
            let errorBody = try await Self.read(stream, limit: Self.maxErrorBytes, throwOnOverflow: false)
            throw Self.mapHTTPError(status: http.statusCode, data: errorBody)
        }

        if http.expectedContentLength > 0, http.expectedContentLength > Int64(Self.maxResponseBytes) {
            throw RelayError.responseTooLarge
        }

        let data = try await Self.read(stream, limit: Self.maxResponseBytes)
        guard !data.isEmpty else { throw RelayError.emptyResponse }

        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw RelayError.decoding
        }
    }

    /// Reads at most `limit` bytes from an async byte stream, honouring task
    /// cancellation. With `throwOnOverflow` the read fails once the cap is
    /// exceeded; otherwise the body is truncated at the cap (used for error
    /// payloads, where the status code matters more than the message).
    private static func read(
        _ stream: URLSession.AsyncBytes,
        limit: Int,
        throwOnOverflow: Bool = true
    ) async throws -> Data {
        var data = Data()
        data.reserveCapacity(min(limit, 64 * 1024))

        do {
            for try await byte in stream {
                if data.count >= limit {
                    if throwOnOverflow { throw RelayError.responseTooLarge }
                    break
                }
                data.append(byte)
                if data.count % Self.cancelCheckStride == 0 {
                    try Task.checkCancellation()
                }
            }
        } catch let error as RelayError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError where error.code == .cancelled {
            throw CancellationError()
        } catch {
            throw RelayError.transport(Self.sanitize(error.localizedDescription))
        }

        return data
    }

    private static func mapHTTPError(status: Int, data: Data) -> RelayError {
        let detail = Self.detail(from: data)
        switch status {
        case 401, 403:
            return .unauthorized
        case 429:
            return .rateLimited(detail)
        default:
            return .server(status: status, detail: detail)
        }
    }

    private static func detail(from data: Data) -> String {
        struct APIError: Decodable { let detail: String }
        guard let decoded = try? JSONDecoder().decode(APIError.self, from: data) else { return "" }
        return sanitize(decoded.detail)
    }

    /// Detail strings come from the server and are shown in the UI: keep them
    /// short and strip control characters.
    private static func sanitize(_ value: String) -> String {
        let collapsed = value
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return String(collapsed.prefix(180))
    }
}

// MARK: - Redirect blocking

/// Redirects are refused: a 30x could otherwise forward the bearer token to a
/// different origin. The 3xx response is handed back to the caller as a failure.
private final class NoRedirectTaskDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

// MARK: - Wire types (namespaced to avoid clashing with shared models)

extension RelayClient {
    struct Health: Decodable {
        let status: String
        let version: String
    }

    struct RegisterResponse: Decodable {
        let uid: String
        let handle: String
        let token: String
    }

    struct DirectoryEntry: Decodable {
        let uid: String
        let handle: String
        let deviceID: UInt32
        let identityKey: String

        enum CodingKeys: String, CodingKey {
            case uid
            case handle
            case deviceID = "device_id"
            case identityKey = "identity_key"
        }
    }

    struct OKResponse: Decodable {
        let ok: Bool
    }

    private struct RegisterBody: Encodable {
        let uid: String
        let handle: String
        let deviceID: UInt32
        let bundle: PublicBundle

        enum CodingKeys: String, CodingKey {
            case uid
            case handle
            case bundle
            case deviceID = "device_id"
        }
    }

    private struct SendBody: Encodable {
        let id: String
        let recipientUID: String
        let recipientDeviceID: UInt32
        let messageType: UInt8
        let ciphertext: String

        enum CodingKeys: String, CodingKey {
            case id
            case ciphertext
            case recipientUID = "recipient_uid"
            case recipientDeviceID = "recipient_device_id"
            case messageType = "message_type"
        }
    }

    private struct SendResponse: Decodable {
        let id: String
        let accepted: Bool
    }

    private struct AckBody: Encodable {
        let ids: [String]
    }

    private struct MessagesResponse: Decodable {
        let messages: [Envelope]
    }
}

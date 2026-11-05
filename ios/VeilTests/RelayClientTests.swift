import XCTest

@testable import Veil

/// URL / cleartext policy for the relay client.
///
/// These tests cover the rules that protect the bearer token from leaving the
/// device in cleartext or being sent to a lookalike host. They do not exercise
/// the network stack (no iOS runtime needed beyond XCTest).
final class RelayURLPolicyTests: XCTestCase {

    // MARK: Normalization

    func testBareHostGetsHTTPSAndTrailingSlash() throws {
        let url = try RelayClient.validateServerURL("relay.example.com")
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "relay.example.com")
        XCTAssertEqual(url.path, "/")
        XCTAssertEqual(url.absoluteString, "https://relay.example.com/")
    }

    func testPathPrefixAndPortSurviveRelativeAPIPaths() throws {
        let url = try RelayClient.validateServerURL("https://relay.example.com:8443/veil")
        XCTAssertEqual(url.port, 8443)
        XCTAssertEqual(url.path, "/veil/")
        XCTAssertEqual(URL(string: "v1/messages", relativeTo: url)?.path, "/veil/v1/messages")
        XCTAssertEqual(URL(string: "v1/messages", relativeTo: url)?.host, "relay.example.com")
    }

    func testQueryAndFragmentAreDiscarded() throws {
        let url = try RelayClient.validateServerURL("https://relay.example.com/base?token=x#frag")
        XCTAssertNil(url.query)
        XCTAssertNil(url.fragment)
        XCTAssertEqual(url.path, "/base/")
    }

    func testEmptyAndCredentialedURLsAreRejected() {
        XCTAssertThrowsError(try RelayClient.validateServerURL("   ")) { error in
            XCTAssertEqual(error as? RelayError, .invalidServerURL)
        }
        XCTAssertThrowsError(try RelayClient.validateServerURL("https://user:pass@relay.example.com")) { error in
            XCTAssertEqual(error as? RelayError, .invalidServerURL)
        }
    }

    // MARK: Transport policy

    func testNonHTTPSchemesAreRejected() {
        for text in ["ftp://relay.example.com", "ws://relay.example.com"] {
            XCTAssertThrowsError(try RelayClient.validateServerURL(text), text) { error in
                XCTAssertEqual(error as? RelayError, .insecureTransport)
            }
        }
        // No host at all: rejected earlier as a malformed URL.
        XCTAssertThrowsError(try RelayClient.validateServerURL("file:///tmp/x")) { error in
            XCTAssertEqual(error as? RelayError, .invalidServerURL)
        }
    }

    func testRemoteCleartextIsAlwaysRejected() {
        XCTAssertThrowsError(try RelayClient.validateServerURL("http://relay.example.com")) { error in
            XCTAssertEqual(error as? RelayError, .insecureTransport)
        }
        XCTAssertThrowsError(try RelayClient.validateServerURL("http://10.0.0.5:8080")) { error in
            XCTAssertEqual(error as? RelayError, .insecureTransport)
        }
    }

    func testLoopbackCleartextFollowsBuildConfiguration() {
        let loopback = [
            "http://127.0.0.1:8080",
            "http://127.0.0.5:1234",
            "http://localhost:8080",
            "http://[::1]:8080"
        ]
        #if DEBUG
        for text in loopback {
            XCTAssertNoThrow(try RelayClient.validateServerURL(text), text)
        }
        #else
        for text in loopback {
            XCTAssertThrowsError(try RelayClient.validateServerURL(text), text) { error in
                XCTAssertEqual(error as? RelayError, .insecureTransport)
            }
        }
        #endif
    }

    // MARK: Loopback host policy

    func testExactLoopbackHosts() {
        XCTAssertTrue(RelayClient.isLoopbackHost("127.0.0.1"))
        XCTAssertTrue(RelayClient.isLoopbackHost("127.0.0.5"))
        XCTAssertTrue(RelayClient.isLoopbackHost("localhost"))
        XCTAssertTrue(RelayClient.isLoopbackHost("LOCALHOST"))
        XCTAssertTrue(RelayClient.isLoopbackHost("::1"))
        XCTAssertTrue(RelayClient.isLoopbackHost("[::1]"))
    }

    func testLookalikeHostsAreNotLoopback() {
        let hostile = [
            "127.attacker.com",
            "127.0.0.1.nip.io",
            "127.0.0.1evil.com",
            "localhost.evil.com",
            "evil.localhost",
            "0127.0.0.1",
            "127.0.0.256",
            "127.0.0",
            "127.0.0.1.",
            "128.0.0.1",
            "0.0.0.0",
            ""
        ]
        for host in hostile {
            XCTAssertFalse(RelayClient.isLoopbackHost(host), host)
        }
    }

    func testLookalikeURLsCannotUseCleartextEvenInDebug() {
        for text in ["http://127.attacker.com", "http://127.0.0.1.nip.io", "http://localhost.evil.com"] {
            XCTAssertThrowsError(try RelayClient.validateServerURL(text), text)
        }
    }
}

/// Handle normalization shared by registration and contact lookup.
final class VeilHandleTests: XCTestCase {

    func testNormalizesPrefixWhitespaceAndCase() throws {
        XCTAssertEqual(try VeilHandle.normalize("@Alice_01"), "alice_01")
        XCTAssertEqual(try VeilHandle.normalize("  bob  "), "bob")
        XCTAssertEqual(try VeilHandle.normalize("A_b_9"), "a_b_9")
    }

    func testBoundaryLengths() throws {
        let three = String(repeating: "a", count: 3)
        let twentyFour = String(repeating: "a", count: 24)
        let twentyFive = String(repeating: "a", count: 25)

        XCTAssertEqual(try VeilHandle.normalize(three), three)
        XCTAssertEqual(try VeilHandle.normalize(twentyFour), twentyFour)
        XCTAssertThrowsError(try VeilHandle.normalize(twentyFive)) { error in
            XCTAssertEqual(error as? AppFailure, .invalidHandle)
        }
    }

    func testRejectsInvalidHandles() {
        let invalid = [
            "",
            "ab",
            "bad handle",
            "bad-handle",
            "bad.dot",
            "Bad!",
            "кирилиця",
            "@@bob",
            "@"
        ]
        for value in invalid {
            XCTAssertThrowsError(try VeilHandle.normalize(value), value) { error in
                XCTAssertEqual(error as? AppFailure, .invalidHandle, value)
            }
        }
    }

    func testRejectsEmojiAndMixedScripts() {
        for value in ["nick😀", "nіck", "nick\u{200B}"] {
            XCTAssertThrowsError(try VeilHandle.normalize(value), value)
        }
    }
}

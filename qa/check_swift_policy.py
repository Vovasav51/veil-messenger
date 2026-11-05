#!/usr/bin/env python3
"""Execute the actual pure-Foundation URL/handle functions on Linux.

This is NOT a substitute for compiling RelayClient, SwiftUI, iOS or crypto.
Only those unchanged source sections are embedded into a tiny test harness.
"""
from pathlib import Path
import os
import subprocess

ROOT = Path(__file__).resolve().parent.parent
CACHE = Path(os.environ.get("VEIL_BUILD_CACHE", Path.home() / ".cache/veil-build")) / "swift-policy-check"


def main():
    relay = (ROOT / "ios/Veil/RelayClient.swift").read_text()
    model = (ROOT / "ios/Veil/AppModel.swift").read_text()
    url_functions = relay.split("    static func validateServerURL", 1)[1].split("    // MARK: API surface", 1)[0]
    # MARK spelling in the app includes a dash after the colon.
    url_functions = url_functions.split("    // MARK: - API surface", 1)[0]
    handles = model.split("enum VeilHandle {", 1)[1].split("// MARK: - Pending registration storage", 1)[0]
    source = """import Foundation
enum RelayError: Error { case invalidServerURL, insecureTransport }
enum AppFailure: Error { case invalidHandle }
enum RelayClient {
    static func validateServerURL""" + url_functions + "\n}\nenum VeilHandle {" + handles + r'''
var checks = 0
func check(_ value: Bool, line: Int = #line) {
    if !value { print("FAIL: policy assertion at harness line \(line)"); exit(1) }
    checks += 1
}
func mustThrow(_ body: () throws -> Void, line: Int = #line) {
    var threw = false
    do { try body() } catch { threw = true }
    check(threw, line: line)
}
check(try RelayClient.validateServerURL("example.com").absoluteString == "https://example.com/")
check(try RelayClient.validateServerURL("https://example.com/prefix").absoluteString == "https://example.com/prefix/")
check(try RelayClient.validateServerURL("https://example.com:443/a?q=secret#fragment").query == nil)
for text in ["", "https://user:secret@example.com", "ftp://example.com", "file:///etc/passwd"] {
    mustThrow { _ = try RelayClient.validateServerURL(text) }
}
for host in ["127.attacker.com", "127.0.0.1.nip.io", "localhost.evil.com", "127.0.0.256", "127.0.0.1.", "0127.0.0.1"] {
    check(!RelayClient.isLoopbackHost(host))
    mustThrow { _ = try RelayClient.validateServerURL("http://" + host) }
}
for host in ["127.0.0.1", "127.1.2.3", "localhost", "[::1]"] {
    check(RelayClient.isLoopbackHost(host))
    #if DEBUG
    check(try RelayClient.validateServerURL("http://" + host).scheme == "http")
    #else
    mustThrow { _ = try RelayClient.validateServerURL("http://" + host) }
    #endif
}
mustThrow { _ = try RelayClient.validateServerURL("http://192.168.1.5") }
check(try VeilHandle.normalize(" @Alice_123 ") == "alice_123")
check(try VeilHandle.normalize(String(repeating: "a", count: 24)).count == 24)
for handle in ["ab", String(repeating: "a", count: 25), "алиса", "abc🙂", "abc\u{200B}", "a bc"] {
    mustThrow { _ = try VeilHandle.normalize(handle) }
}
print("PASS: \(checks) real Foundation URL/handle policy assertions")
'''
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / "main.swift"
    path.write_text(source)
    for config, flags in (("debug", ["-D", "DEBUG"]), ("release", [])):
        print(config, flush=True)
        # The lab restricts the system linker to root. Swift's interpreter runs
        # pure Foundation without changing linker/host hardening permissions.
        subprocess.run(["swift", *flags, str(path)], check=True)


if __name__ == "__main__":
    main()

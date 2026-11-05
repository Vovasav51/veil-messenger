#!/usr/bin/env bash
#
# Veil iOS build helper.
#
# Requires macOS + Xcode. The Linux development host can only lint this file
# (`bash -n`, `shellcheck`); it cannot run any of these modes and cannot
# produce an installable iPhone application.
#
# Modes:
#   prepare              xcodegen + pod install only (used by CI caching steps)
#   simulator            Debug build for generic iOS Simulator (unsigned)
#   test                 Debug build + XCTest on a concrete simulator
#   device-unsigned      Release compile for generic/platform=iOS with signing
#                        fully disabled. Produces a .xcarchive that is NOT
#                        installable on a device: no signature, no profile.
#   archive              Release archive with real signing (automatic by
#                        default, manual when a profile/identity is supplied)
#   export               Export an IPA from build/Veil.xcarchive
#   third-party-sources  Bundle AGPL licence + pinned libsignal provenance
#   help
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOS="$ROOT/ios"
BUILD="$ROOT/build"
LOGDIR="$BUILD/logs"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
APP_BUNDLE_NAME="Veil"

MODE="${1:-simulator}"

log() { printf '[veil-ios] %s\n' "$*" >&2; }
die() { printf '[veil-ios] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  # Print the header comment block only (stops at the first non-comment line).
  awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "${BASH_SOURCE[0]}"
}

if [[ "${MODE}" == "help" || "${MODE}" == "-h" || "${MODE}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  cat >&2 <<'EOF'
[veil-ios] ERROR: iOS builds require macOS with Xcode and the iOS SDK.
[veil-ios] This Linux host cannot compile, test, archive or sign iOS code, and
[veil-ios] must not be used to produce a "fake IPA". Use a Mac or the
[veil-ios] manual GitHub Actions workflow described in docs/IOS_BUILD.md.
EOF
  exit 2
fi

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "missing '$1'. Install it first (see docs/IOS_BUILD.md)."
}

require_xcode_tools() {
  for tool in xcodebuild xcrun xcodegen pod; do
    require_tool "$tool"
  done
}

mkdir -p "$LOGDIR"

# Runs xcodebuild, streams output and always keeps a copy for CI artifacts.
run_xcodebuild() {
  local name="$1" logfile; shift
  logfile="$LOGDIR/${name}-${STAMP}.log"
  {
    printf '===== veil ios %s =====\n' "$name"
    printf 'date: %s\n' "$STAMP"
    printf 'command: xcodebuild'
    printf ' %q' "$@"
    printf '\n--- toolchain ---\n'
    xcodebuild -version || true
    printf '\n--- output ---\n'
  } >>"$logfile"
  log "xcodebuild ($name) -> ${logfile#"$ROOT"/}"
  local rc=0
  xcodebuild "$@" 2>&1 | tee -a "$logfile" || rc=${PIPESTATUS[0]}
  return "$rc"
}

prepare() {
  if [[ "${VEIL_SKIP_PREPARE:-0}" == "1" ]]; then
    log "prepare skipped (VEIL_SKIP_PREPARE=1)"
    return 0
  fi
  cd "$IOS"
  local plog="$LOGDIR/prepare-${STAMP}.log"
  log "xcodegen generate"
  xcodegen generate 2>&1 | tee -a "$plog"
  # Podfile.lock must be committed for reproducible dependency resolution.
  # --deployment makes a drifted lockfile a hard failure instead of a silent
  # "works on my machine" upgrade.
  if [[ -f Podfile.lock ]]; then
    log "pod install --deployment (Podfile.lock is authoritative)"
    COCOAPODS_DISABLE_STATS=1 pod install --deployment 2>&1 | tee -a "$plog"
  else
    log "pod install (no Podfile.lock yet; commit the generated one)"
    COCOAPODS_DISABLE_STATS=1 pod install 2>&1 | tee -a "$plog"
  fi
}

workspace_args() {
  [[ -d "$IOS/Veil.xcworkspace" ]] || die "ios/Veil.xcworkspace is missing; run 'scripts/ios-build.sh prepare' first."
}

read_plist() { # read_plist <plist> <key-path>; prints raw value, fails if absent
  plutil -extract "$2" raw -o - "$1" 2>/dev/null
}

# Decodes an embedded provisioning profile into a temporary plist.
decode_profile() { # decode_profile <mobileprovision> <out-plist>
  security cms -D -i "$1" >"$2" 2>/dev/null || die "cannot decode provisioning profile: $1"
  [[ -s "$2" ]] || die "provisioning profile decoded to an empty plist: $1"
}

# Refuses an app whose embedded profile belongs to another team/bundle id.
# This catches the classic CI mistake of picking the wrong provisioned profile.
verify_signed_app() { # verify_signed_app <app-path> <team-id> <bundle-id>
  local app="$1" team="$2" bundle="$3"
  local profile="$app/embedded.mobileprovision"
  [[ -d "$app" ]] || die "expected app bundle not found: $app"
  [[ -f "$profile" ]] || die "signed app has no embedded.mobileprovision: $app"

  local tmp; tmp="$(mktemp "${TMPDIR:-/tmp}/veil-profile.XXXXXX")"
  local rc=0
  decode_profile "$profile" "$tmp" || rc=$?
  if [[ $rc -ne 0 ]]; then
    rm -f "$tmp"
    die "cannot decode embedded.mobileprovision"
  fi

  local pteam pappid pbundle pexp
  pteam="$(read_plist "$tmp" 'TeamIdentifier.0')" || true
  [[ "$pteam" == "$team" ]] || { rm -f "$tmp"; die "profile team '${pteam:-<none>}' does not match expected '${team}'"; }

  pappid="$(read_plist "$tmp" 'Entitlements.application-identifier')" || true
  case "$pappid" in
    "$team.$bundle") ;;
    "$team.*") ;;  # wildcard profile: concrete id is checked against the signature below
    *) rm -f "$tmp"; die "profile application-identifier '${pappid:-<none>}' does not match '${team}.${bundle}'" ;;
  esac

  # The binary must actually carry the concrete application-identifier, which
  # also proves that codesign really signed this build (not just the archive).
  local ent_file; ent_file="$(mktemp "${TMPDIR:-/tmp}/veil-ent.XXXXXX")"
  codesign -d --entitlements :- "$app" 2>/dev/null | sed -n '/<?xml/,$p' >"$ent_file" || true
  local signed_appid=""
  signed_appid="$(read_plist "$ent_file" 'application-identifier')" || true
  rm -f "$ent_file"
  [[ "$signed_appid" == "$team.$bundle" ]] \
    || { rm -f "$tmp"; die "signed entitlements application-identifier '${signed_appid:-<none>}' does not match '${team}.${bundle}'"; }

  codesign --verify --strict "$app" >/dev/null 2>&1 \
    || { rm -f "$tmp"; die "codesign --verify --strict failed for $app"; }

  pbundle="$(read_plist "$app/Info.plist" 'CFBundleIdentifier')" || true
  [[ "$pbundle" == "$bundle" ]] \
    || { rm -f "$tmp"; die "built bundle id '${pbundle:-<none>}' does not match expected '${bundle}'"; }

  pexp="$(read_plist "$tmp" 'ExpirationDate')" || true
  if [[ -n "${pexp:-}" ]]; then
    local now; now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    [[ "$pexp" > "$now" ]] || { rm -f "$tmp"; die "provisioning profile expired at ${pexp}"; }
  fi
  rm -f "$tmp"
  log "signing verified: team=$team bundle=$bundle profile_ok"
}

verify_unsigned_archive() { # verify_unsigned_archive <xcarchive>
  local archive="$1"
  local app="$archive/Products/Applications/${APP_BUNDLE_NAME}.app"
  [[ -d "$app" ]] || die "unsigned archive is missing ${APP_BUNDLE_NAME}.app: $archive"
  [[ -x "$app/${APP_BUNDLE_NAME}" ]] || die "unsigned archive has no ${APP_BUNDLE_NAME} executable"

  local material
  material="$(find "$app" \( -name '_CodeSignature' -o -name 'CodeResources' -o -name 'embedded.mobileprovision' \) -print 2>/dev/null | head -n 1 || true)"
  [[ -z "$material" ]] || die "expected an unsigned archive but found signing material: $material"

  local archs
  archs="$(lipo -archs "$app/${APP_BUNDLE_NAME}" 2>/dev/null || true)"
  [[ "$archs" == *arm64* ]] || die "device binary is not arm64 (found: '${archs:-<none>}')"

  read_plist "$app/Info.plist" 'CFBundleIdentifier' >/dev/null \
    || die "built Info.plist is unreadable"

  cat >"$archive/DO-NOT-INSTALL-UNSIGNED.txt" <<'EOF'
UNSIGNED BUILD - COMPILE VALIDATION ONLY - NOT INSTALLABLE ON ANY IPHONE

This .xcarchive was produced with CODE_SIGNING_ALLOWED=NO. It proves that the
Release configuration compiles against the real iOS device SDK and that an
arm64 binary was linked. It contains:

  * no code signature (_CodeSignature / CodeResources)
  * no embedded.mobileprovision
  * no entitlement grant

iOS refuses to launch such a binary. There is no supported way to install it
via Xcode, Apple Configurator, TestFlight or App Store Connect. Do not rename
it to .ipa and do not distribute it as an app.

For an installable build see docs/IOS_BUILD.md ("Підписаний артефакт").
EOF

  log "unsigned device compile validated: $archive (arm64, no signature, NOT installable)"
}

case "$MODE" in
  prepare)
    require_xcode_tools
    prepare
    ;;

  simulator)
    require_xcode_tools
    prepare
    workspace_args
    run_xcodebuild simulator -workspace "$IOS/Veil.xcworkspace" -scheme Veil \
      -configuration Debug \
      -sdk iphonesimulator \
      -destination 'generic/platform=iOS Simulator' \
      -derivedDataPath "$BUILD/DerivedData" \
      CODE_SIGNING_ALLOWED=NO \
      build
    log "simulator app: build/DerivedData/Build/Products/Debug-iphonesimulator/${APP_BUNDLE_NAME}.app (simulator only)"
    ;;

  test)
    require_xcode_tools
    prepare
    workspace_args
    destination="${VEIL_TEST_DESTINATION:-}"
    if [[ -z "$destination" ]]; then
      destination="$(xcrun simctl list devices available --json | python3 -c '
import json, sys
data = json.load(sys.stdin)
for runtime, devices in sorted(data.get("devices", {}).items()):
    for device in devices:
        if device.get("isAvailable") and "iPhone" in device.get("name", ""):
            print("platform=iOS Simulator,id=" + device["udid"])
            raise SystemExit(0)
raise SystemExit("no available iPhone simulator; install an iOS runtime in Xcode")
')" || die "no available iPhone simulator runtime found"
    fi
    log "test destination: $destination"
    result_bundle="$BUILD/TestResults-${STAMP}.xcresult"
    rm -rf "$result_bundle"
    run_xcodebuild test -workspace "$IOS/Veil.xcworkspace" -scheme Veil \
      -configuration Debug \
      -destination "$destination" \
      -derivedDataPath "$BUILD/DerivedData" \
      -resultBundlePath "$result_bundle" \
      -enableCodeCoverage YES \
      CODE_SIGNING_ALLOWED=NO \
      test
    log "test results: ${result_bundle#"$ROOT"/}"
    ;;

  device-unsigned)
    require_xcode_tools
    prepare
    workspace_args
    archive="$BUILD/Veil-unsigned.xcarchive"
    rm -rf "$archive"
    run_xcodebuild device-unsigned -workspace "$IOS/Veil.xcworkspace" -scheme Veil \
      -configuration Release \
      -destination 'generic/platform=iOS' \
      -archivePath "$archive" \
      -derivedDataPath "$BUILD/DerivedData-unsigned" \
      CODE_SIGNING_ALLOWED=NO \
      CODE_SIGNING_REQUIRED=NO \
      CODE_SIGN_IDENTITY= \
      EXPANDED_CODE_SIGN_IDENTITY= \
      DEVELOPMENT_TEAM= \
      PROVISIONING_PROFILE_SPECIFIER= \
      archive
    verify_unsigned_archive "$archive"
    ;;

  archive)
    require_xcode_tools
    : "${VEIL_APPLE_TEAM_ID:?Set VEIL_APPLE_TEAM_ID (10-character Apple Developer team id).}"
    : "${VEIL_BUNDLE_ID:?Set VEIL_BUNDLE_ID to your own registered unique bundle identifier.}"
    [[ "$VEIL_APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] \
      || die "VEIL_APPLE_TEAM_ID must be a 10-character team id, got '${VEIL_APPLE_TEAM_ID}'"
    [[ "$VEIL_BUNDLE_ID" == *.* ]] \
      || die "VEIL_BUNDLE_ID must be a reverse-DNS identifier, got '${VEIL_BUNDLE_ID}'"
    prepare
    workspace_args
    archive="$BUILD/Veil.xcarchive"
    rm -rf "$archive"

    signing_args=(
      "DEVELOPMENT_TEAM=$VEIL_APPLE_TEAM_ID"
      "PRODUCT_BUNDLE_IDENTIFIER=$VEIL_BUNDLE_ID"
    )
    allow_updates=()
    if [[ -n "${VEIL_PROVISIONING_PROFILE_SPECIFIER:-}" || -n "${VEIL_SIGNING_IDENTITY:-}" ]]; then
      [[ -n "${VEIL_PROVISIONING_PROFILE_SPECIFIER:-}" ]] \
        || die "manual signing requires VEIL_PROVISIONING_PROFILE_SPECIFIER (or unset VEIL_SIGNING_IDENTITY)"
      signing_args+=(
        "CODE_SIGN_STYLE=Manual"
        "CODE_SIGN_IDENTITY=${VEIL_SIGNING_IDENTITY:-Apple Distribution}"
        "PROVISIONING_PROFILE_SPECIFIER=$VEIL_PROVISIONING_PROFILE_SPECIFIER"
      )
      log "archive with manual signing (identity: ${VEIL_SIGNING_IDENTITY:-Apple Distribution})"
    else
      signing_args+=("CODE_SIGN_STYLE=Automatic")
      allow_updates+=("-allowProvisioningUpdates")
      log "archive with automatic signing; Xcode account or App Store Connect key must already be configured"
    fi

    run_xcodebuild archive -workspace "$IOS/Veil.xcworkspace" -scheme Veil \
      -configuration Release \
      -destination 'generic/platform=iOS' \
      -archivePath "$archive" \
      -derivedDataPath "$BUILD/DerivedData" \
      "${signing_args[@]}" \
      ${allow_updates[@]+"${allow_updates[@]}"} \
      archive
    verify_signed_app "$archive/Products/Applications/${APP_BUNDLE_NAME}.app" \
      "$VEIL_APPLE_TEAM_ID" "$VEIL_BUNDLE_ID"
    log "signed archive: ${archive#"$ROOT"/} (export with 'scripts/ios-build.sh export')"
    ;;

  export)
    require_tool xcodebuild
    : "${VEIL_EXPORT_OPTIONS:?Set VEIL_EXPORT_OPTIONS to an ExportOptions.plist (see ios/ExportOptions.example.plist).}"
    [[ -f "$VEIL_EXPORT_OPTIONS" ]] || die "ExportOptions plist not found: $VEIL_EXPORT_OPTIONS"
    archive="${VEIL_ARCHIVE_PATH:-$BUILD/Veil.xcarchive}"
    [[ -d "$archive" ]] || die "archive not found: $archive (run 'scripts/ios-build.sh archive' first)"
    out="$BUILD/export"
    rm -rf "$out"
    mkdir -p "$out"
    extra=()
    [[ "${VEIL_ALLOW_PROVISIONING_UPDATES:-0}" == "1" ]] && extra+=("-allowProvisioningUpdates")
    run_xcodebuild export \
      -exportArchive \
      -archivePath "$archive" \
      -exportPath "$out" \
      -exportOptionsPlist "$VEIL_EXPORT_OPTIONS" \
      ${extra[@]+"${extra[@]}"}
    shopt -s nullglob
    ipas=("$out"/*.ipa)
    shopt -u nullglob
    [[ ${#ipas[@]} -eq 1 ]] || die "expected exactly one .ipa in $out, found ${#ipas[@]}"
    ipa="${ipas[0]}"
    [[ -s "$ipa" ]] || die "exported IPA is empty: $ipa"
    unpack="$BUILD/export-unpacked"
    rm -rf "$unpack"; mkdir -p "$unpack"
    ditto -x -k "$ipa" "$unpack"
    [[ -d "$unpack/Payload/${APP_BUNDLE_NAME}.app" ]] || die "IPA payload is missing ${APP_BUNDLE_NAME}.app"
    : "${VEIL_APPLE_TEAM_ID:?Set VEIL_APPLE_TEAM_ID to verify the exported IPA.}"
    : "${VEIL_BUNDLE_ID:?Set VEIL_BUNDLE_ID to verify the exported IPA.}"
    verify_signed_app "$unpack/Payload/${APP_BUNDLE_NAME}.app" "$VEIL_APPLE_TEAM_ID" "$VEIL_BUNDLE_ID"
    ( cd "$out" && shasum -a 256 ./*.ipa | tee "$out/SHA256SUMS.txt" )
    log "IPA: ${ipa#"$ROOT"/} (signed; distribution method depends on the ExportOptions plist)"
    ;;

  third-party-sources)
    # AGPL-3.0 corresponding-source bundle: our licences/notices, the exact
    # dependency pin, and the libsignal pod checkout that was actually compiled.
    out="$BUILD/veil-third-party-agpl-sources.tar.gz"
    rm -f "$out"
    stage="$BUILD/third-party-sources"
    rm -rf "$stage"; mkdir -p "$stage"
    cp "$ROOT/licenses/AGPL-3.0.txt" "$stage/" 2>/dev/null || true
    cp "$ROOT/THIRD_PARTY_NOTICES.md" "$stage/" 2>/dev/null || true
    cp "$IOS/Podfile" "$stage/" 2>/dev/null || true
    cp "$IOS/Podfile.lock" "$stage/" 2>/dev/null || true
    if [[ -d "$IOS/Pods/Local Podspecs" ]]; then
      mkdir -p "$stage/local-podspecs"
      cp "$IOS/Pods/Local Podspecs"/*.json "$stage/local-podspecs/" 2>/dev/null || true
    fi
    rev="$(git -C "$IOS/Pods/LibSignalClient" rev-parse HEAD 2>/dev/null || echo 'fc90b90fa2b9c37822fa47ba0e0dcdf387a0c071')"
    {
      printf 'Veil third-party AGPL-3.0 source provenance\n'
      printf 'generated: %s\n' "$STAMP"
      printf 'libsignal repository: https://github.com/signalapp/libsignal.git\n'
      printf 'libsignal commit: %s\n' "$rev"
      printf 'libsignal FFI archive SHA-256: %s\n' 'ddfa5ac6fd6e0da9ebe4eb23890af048140aec1a3e916d3eccadc1036627152f'
      printf 'libsignal version: 0.106.0\n\n'
      printf 'Contents: AGPL-3.0.txt, THIRD_PARTY_NOTICES.md, Podfile, Podfile.lock,\n'
      printf 'Local Podspecs, and (when present) the libsignal source checkout that\n'
      printf 'this build compiled. The Rust FFI binary is a prebuilt upstream artifact;\n'
      printf 'its source is the pinned commit above.\n'
      printf '\nTo fetch the identical source without GitHub Actions:\n'
      printf '  git clone https://github.com/signalapp/libsignal.git\n'
      printf '  git -C libsignal checkout %s\n' "$rev"
    } >"$stage/PROVENANCE.txt"
    if [[ -d "$IOS/Pods/LibSignalClient" ]]; then
      mkdir -p "$stage/libsignal"
      ( cd "$IOS/Pods/LibSignalClient" && tar -cf - \
          --exclude='.git' --exclude='target' --exclude='*.o' --exclude='*.a' . ) \
        | ( cd "$stage/libsignal" && tar -xf - ) || log "warning: partial libsignal source copy"
    else
      log "warning: ios/Pods/LibSignalClient absent; provenance pointer only (run 'prepare' first)"
    fi
    ( cd "$stage" && tar -czf "$out" . )
    log "AGPL source bundle: ${out#"$ROOT"/} ($(du -h "$out" | cut -f1))"
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac

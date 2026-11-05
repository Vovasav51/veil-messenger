#!/usr/bin/env bash
#
# Veil: CI-only signed iOS archive + IPA export.
#
# RUNS ON macOS ONLY. Never run this on the Linux development host: it requires
# `security`, `codesign` and Xcode.
#
# This script never asks for, prompts for, or prints credentials. It reads an
# already-supplied certificate and provisioning profile from the environment
# (populated from GitHub Actions secrets), uses them inside a throw-away
# keychain, exports the IPA and destroys every secret artefact on exit.
#
# Required environment:
#   IOS_CERT_P12_BASE64            base64 of a .p12 with the signing identity
#   IOS_CERT_PASSWORD              password of that .p12
#   IOS_PROVISIONING_PROFILE_BASE64 base64 of the matching .mobileprovision
#   IOS_TEAM_ID                    10-character Apple Developer team id
#   IOS_BUNDLE_ID                  reverse-DNS bundle id registered for that team
# Optional:
#   IOS_EXPORT_METHOD              development | ad-hoc | app-store | enterprise
#                                  (default: development)
#   IOS_SIGNING_IDENTITY           default: "Apple Distribution"
#   IOS_ARCHIVE_PATH               default: <repo>/build/Veil.xcarchive
#
# Exit codes: 2 = wrong platform / bad invocation, 1 = signing setup or build
# refused (for example a profile whose team or bundle id does not match).
#
set -euo pipefail
set +x

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLISTBUDDY="${PLISTBUDDY:-/usr/libexec/PlistBuddy}"
MODE="${IOS_EXPORT_METHOD:-development}"
SIGNING_IDENTITY="${IOS_SIGNING_IDENTITY:-Apple Distribution}"
ARCHIVE="${IOS_ARCHIVE_PATH:-$ROOT/build/Veil.xcarchive}"
EXPORT_DIR="$ROOT/build/export"

log() { printf '[veil-sign] %s\n' "$*" >&2; }
die() { printf '[veil-sign] REFUSED: %s\n' "$*" >&2; exit 1; }

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo '[veil-sign] ERROR: this script requires macOS with Xcode.' >&2
  exit 2
fi

for tool in security codesign plutil xcodebuild; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "missing '$tool'; Xcode command line tools are required"
done

# ---------------------------------------------------------------- input checks

missing=()
for name in IOS_CERT_P12_BASE64 IOS_CERT_PASSWORD IOS_PROVISIONING_PROFILE_BASE64 \
            IOS_TEAM_ID IOS_BUNDLE_ID; do
  # Indirect expansion via eval: macOS /bin/bash 3.2 has no reliable ${!name:-}.
  eval "current=\"\${$name:-}\""
  if [[ -z "$current" ]]; then
    missing+=("$name")
  fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
  # Print names only, never values.
  die "missing required environment variable(s): ${missing[*]}
Create them as repository/environment secrets; see docs/IOS_BUILD.md."
fi

[[ "$IOS_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]] \
  || die "IOS_TEAM_ID must be a 10-character uppercase team id"
[[ "$IOS_BUNDLE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9.-]+$ && "$IOS_BUNDLE_ID" == *.* ]] \
  || die "IOS_BUNDLE_ID must be a reverse-DNS identifier"

case "$MODE" in
  development|ad-hoc|app-store|enterprise) ;;
  *) die "IOS_EXPORT_METHOD must be development, ad-hoc, app-store or enterprise (got '$MODE')" ;;
esac

case "$SIGNING_IDENTITY" in
  "Apple Distribution"|"iPhone Distribution"|"Apple Development"|"iPhone Developer") ;;
  *) log "warning: unusual signing identity '$SIGNING_IDENTITY'" ;;
esac

# ------------------------------------------------------- ephemeral keychain

umask 077
WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/veil-sign.XXXXXX")" \
  || die "cannot create a private temporary directory"
KEYCHAIN_PATH="$WORK/veil-signing.keychain-db"
KEYCHAIN_PASSWORD="$(openssl rand -hex 24)"
ORIG_DEFAULT=""
ORIG_SEARCH_CHAIN=()
PROFILE_DEST=""
PROFILE_BACKUP=""
PROFILE_DIR_CREATED=0

restore_keychain_state() {
  if [[ -n "$ORIG_DEFAULT" ]]; then
    security default-keychain -d user -s "$ORIG_DEFAULT" >/dev/null 2>&1 || true
  fi
  if [[ ${#ORIG_SEARCH_CHAIN[@]} -gt 0 ]]; then
    security list-keychains -d user -s "${ORIG_SEARCH_CHAIN[@]}" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  set +e
  trap - EXIT INT TERM
  log "cleanup: restoring keychain search list"
  restore_keychain_state

  if [[ -f "$KEYCHAIN_PATH" ]]; then
    security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1
    log "cleanup: temporary keychain deleted"
  fi
  if security list-keychains -d user 2>/dev/null | grep -q 'veil-signing'; then
    log "WARNING: temporary keychain still referenced by the search list"
  fi

  if [[ -n "$PROFILE_DEST" ]]; then
    if [[ -n "$PROFILE_BACKUP" && -f "$PROFILE_BACKUP" ]]; then
      mv -f "$PROFILE_BACKUP" "$PROFILE_DEST" 2>/dev/null
      log "cleanup: previous profile restored (same UUID was already installed)"
    else
      rm -f "$PROFILE_DEST"
      log "cleanup: provisioning profile removed"
    fi
  fi
  if [[ "$PROFILE_DIR_CREATED" == "1" ]]; then
    rmdir "$HOME/Library/MobileDevice/Provisioning Profiles" 2>/dev/null
    rmdir "$HOME/Library/MobileDevice" 2>/dev/null
  fi

  # Certificates, profile copy, generated plists and derived data pins.
  rm -rf "$WORK"
  log "cleanup: temporary directory removed"
}
trap cleanup EXIT INT TERM

while IFS= read -r line; do
  line="${line#"${line%%[![:space:]]*}"}"   # ltrim
  line="${line%\"}"; line="${line#\"}"      # strip surrounding quotes
  [[ -n "$line" ]] && ORIG_SEARCH_CHAIN+=("$line")
done < <(security list-keychains -d user 2>/dev/null || true)
ORIG_DEFAULT="$(security default-keychain -d user 2>/dev/null | tr -d '"' | sed 's/^[[:space:]]*//' || true)"

# ------------------------------------------------------------ import identity

decode_b64() { # decode_b64 <dest>
  tr -d ' \t\r\n' | openssl base64 -d -A >"$1"
}

if ! printf '%s' "$IOS_CERT_P12_BASE64" | decode_b64 "$WORK/signing.p12"; then
  die "IOS_CERT_P12_BASE64 is not valid base64"
fi
[[ -s "$WORK/signing.p12" ]] || die "decoded certificate file is empty"

# -P puts the password in this process's argv for a few milliseconds on an
# ephemeral single-tenant runner. There is no stdin alternative for `security`.
if ! security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" >/dev/null 2>&1; then
  die "cannot create the temporary keychain"
fi
security set-keychain-settings -lut 3600 "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" >/dev/null 2>&1 \
  || die "cannot unlock the temporary keychain"

if [[ ${#ORIG_SEARCH_CHAIN[@]} -gt 0 ]]; then
  security list-keychains -d user -s "$KEYCHAIN_PATH" "${ORIG_SEARCH_CHAIN[@]}" >/dev/null 2>&1 \
    || die "cannot extend the keychain search list"
else
  security list-keychains -d user -s "$KEYCHAIN_PATH" >/dev/null 2>&1 \
    || die "cannot extend the keychain search list"
fi
if [[ -n "$ORIG_DEFAULT" ]]; then
  security default-keychain -d user -s "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
fi

security import "$WORK/signing.p12" -k "$KEYCHAIN_PATH" -P "$IOS_CERT_PASSWORD" \
  -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1 \
  || die "cannot import the certificate; check IOS_CERT_PASSWORD and that the file is a real .p12"
rm -f "$WORK/signing.p12"

security set-key-partition-list -S apple-tool:,apple:,codesign: \
  -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" >/dev/null 2>&1 \
  || die "cannot authorise the imported key for codesign (set-key-partition-list failed)"

if ! security find-identity -v -p codesigning "$KEYCHAIN_PATH" | grep -qE '[1-9][0-9]* valid identities found'; then
  security find-identity -v -p codesigning "$KEYCHAIN_PATH" >&2 || true
  die "the imported certificate is not a valid code-signing identity (missing private key?)"
fi
log "identity imported into the temporary keychain"

# ------------------------------------------------------------ provisioning

if ! printf '%s' "$IOS_PROVISIONING_PROFILE_BASE64" | decode_b64 "$WORK/profile.mobileprovision"; then
  die "IOS_PROVISIONING_PROFILE_BASE64 is not valid base64"
fi
[[ -s "$WORK/profile.mobileprovision" ]] || die "decoded provisioning profile is empty"

security cms -D -i "$WORK/profile.mobileprovision" >"$WORK/profile.plist" 2>/dev/null \
  || die "the provisioning profile is not a signed Apple profile"
plutil -lint "$WORK/profile.plist" >/dev/null 2>&1 \
  || die "the decoded provisioning profile is not a valid plist"

plist_get() { plutil -extract "$1" raw -o - "$WORK/profile.plist" 2>/dev/null; }

PROFILE_TEAM="$(plist_get TeamIdentifier.0 || true)"
PROFILE_APPID="$(plist_get Entitlements.application-identifier || true)"
PROFILE_UUID="$(plist_get UUID || true)"
PROFILE_NAME="$(plist_get Name || true)"
PROFILE_EXPIRY="$(plist_get ExpirationDate || true)"

[[ -n "$PROFILE_UUID" && -n "$PROFILE_NAME" ]] || die "profile has no UUID or Name; refusing to install it"
[[ "$PROFILE_TEAM" == "$IOS_TEAM_ID" ]] \
  || die "profile team '${PROFILE_TEAM:-<none>}' does not match IOS_TEAM_ID '$IOS_TEAM_ID'"

case "$PROFILE_APPID" in
  "$IOS_TEAM_ID.$IOS_BUNDLE_ID") ;;
  "$IOS_TEAM_ID.*")
    log "note: profile uses a wildcard App ID; the signed binary will be re-checked for $IOS_BUNDLE_ID"
    ;;
  *) die "profile application-identifier '${PROFILE_APPID:-<none>}' does not cover '$IOS_TEAM_ID.$IOS_BUNDLE_ID'" ;;
esac

if [[ -n "$PROFILE_EXPIRY" ]]; then
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  [[ "$PROFILE_EXPIRY" > "$now" ]] || die "provisioning profile expired at $PROFILE_EXPIRY"
fi

has_device_list=0
plutil -extract ProvisionedDevices raw -o - "$WORK/profile.plist" >/dev/null 2>&1 && has_device_list=1
all_devices="$(plist_get ProvisionsAllDevices || true)"

case "$MODE" in
  development|ad-hoc)
    [[ "$all_devices" != "true" ]] || die "profile is an enterprise (ProvisionsAllDevices) profile, not $MODE"
    [[ "$has_device_list" == "1" ]] || die "profile has no ProvisionedDevices; it cannot be used for $MODE"
    ;;
  enterprise)
    [[ "$all_devices" == "true" ]] || die "profile is not an enterprise (ProvisionsAllDevices) profile"
    ;;
  app-store)
    [[ "$has_device_list" == "0" && "$all_devices" != "true" ]] \
      || die "profile looks like development/ad-hoc/enterprise, not app-store"
    ;;
esac
log "profile accepted: team=$IOS_TEAM_ID bundle-check=ok method=$MODE (development and ad-hoc share the same profile shape)"

PROFILE_DIR="$HOME/Library/MobileDevice/Provisioning Profiles"
if [[ ! -d "$PROFILE_DIR" ]]; then
  mkdir -p "$PROFILE_DIR" && PROFILE_DIR_CREATED=1
fi
PROFILE_DEST="$PROFILE_DIR/$PROFILE_UUID.mobileprovision"
if [[ -f "$PROFILE_DEST" ]]; then
  PROFILE_BACKUP="$WORK/previous-profile.mobileprovision"
  cp "$PROFILE_DEST" "$PROFILE_BACKUP"
fi
cp "$WORK/profile.mobileprovision" "$PROFILE_DEST"
chmod 600 "$PROFILE_DEST"

# --------------------------------------------------------------- build + export

VEIL_APPLE_TEAM_ID="$IOS_TEAM_ID" \
VEIL_BUNDLE_ID="$IOS_BUNDLE_ID" \
VEIL_SIGNING_IDENTITY="$SIGNING_IDENTITY" \
VEIL_PROVISIONING_PROFILE_SPECIFIER="$PROFILE_NAME" \
bash "$ROOT/scripts/ios-build.sh" archive

[[ -d "$ARCHIVE" ]] || die "expected archive was not created: $ARCHIVE"

EXPORT_OPTIONS="$WORK/ExportOptions.plist"
cp "$ROOT/ios/ExportOptions.example.plist" "$EXPORT_OPTIONS" \
  || die "missing ios/ExportOptions.example.plist"
"$PLISTBUDDY" -c "Set :method $MODE" "$EXPORT_OPTIONS" >/dev/null \
  || die "cannot set export method in ExportOptions"
"$PLISTBUDDY" -c "Set :teamID $IOS_TEAM_ID" "$EXPORT_OPTIONS" >/dev/null \
  || die "cannot set teamID in ExportOptions"
"$PLISTBUDDY" -c "Set :signingStyle manual" "$EXPORT_OPTIONS" >/dev/null \
  || die "cannot set signingStyle in ExportOptions"
"$PLISTBUDDY" -c "Delete :provisioningProfiles" "$EXPORT_OPTIONS" >/dev/null 2>&1 || true
"$PLISTBUDDY" -c "Add :provisioningProfiles dict" "$EXPORT_OPTIONS" >/dev/null \
  || die "cannot create provisioningProfiles mapping"
"$PLISTBUDDY" -c "Add :provisioningProfiles:$IOS_BUNDLE_ID string $PROFILE_NAME" "$EXPORT_OPTIONS" >/dev/null \
  || die "cannot map bundle id to provisioning profile"
plutil -lint "$EXPORT_OPTIONS" >/dev/null || die "generated ExportOptions.plist is invalid"

rm -rf "$EXPORT_DIR"
VEIL_EXPORT_OPTIONS="$EXPORT_OPTIONS" \
VEIL_ARCHIVE_PATH="$ARCHIVE" \
VEIL_ALLOW_PROVISIONING_UPDATES=0 \
VEIL_APPLE_TEAM_ID="$IOS_TEAM_ID" \
VEIL_BUNDLE_ID="$IOS_BUNDLE_ID" \
bash "$ROOT/scripts/ios-build.sh" export

log "signed export complete; artefacts under build/export"
log "temporary keychain and provisioning profile will be destroyed on exit"

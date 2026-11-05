#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="${VEIL_BUILD_CACHE:-$HOME/.cache/veil-build}"
if [[ -f "$CACHE/env.sh" ]]; then
  source "$CACHE/env.sh"
fi
command -v gradle >/dev/null || { echo 'Gradle 8.9 required. See docs/ANDROID_BUILD.md.' >&2; exit 2; }
: "${JAVA_HOME:?Set JAVA_HOME to a full JDK 17 or 21, not a JRE.}"
: "${ANDROID_HOME:?Set ANDROID_HOME to Android SDK with platform 35 and build-tools 35.0.0.}"
# This lab mounts /tmp noexec. JNI libraries need an executable extraction path.
mkdir -p "$CACHE/tmp"
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Djava.io.tmpdir=$CACHE/tmp"
case "${1:-debug}" in
  debug) TASK=assembleDebug ;;
  test) TASK=testDebugUnitTest ;;
  lint) TASK=lintDebug ;;
  *) echo 'Usage: scripts/android-build.sh [debug|test|lint]' >&2; exit 2 ;;
esac
gradle -p "$ROOT/android" --no-daemon --console=plain "$TASK"
if [[ "$TASK" == assembleDebug ]]; then
  mkdir -p "$ROOT/dist"
  cp "$ROOT/android/app/build/outputs/apk/debug/app-debug.apk" "$ROOT/dist/Veil-0.1.0-dev.apk"
  echo "Built $ROOT/dist/Veil-0.1.0-dev.apk (development/debug signature, NOT production)"
fi

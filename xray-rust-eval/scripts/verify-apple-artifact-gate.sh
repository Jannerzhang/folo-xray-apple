#!/usr/bin/env bash
set -euo pipefail

XCFRAMEWORK_PATH="${1:?usage: verify-apple-artifact-gate.sh /path/to/XrayRust.xcframework}"
if [[ ! -d "$XCFRAMEWORK_PATH" || "$XCFRAMEWORK_PATH" != *.xcframework ]]; then
  echo "verified Apple XCFramework directory is required: $XCFRAMEWORK_PATH" >&2
  exit 2
fi

PLIST="$XCFRAMEWORK_PATH/Info.plist"
[[ -f "$PLIST" ]] || { echo "missing XCFramework Info.plist" >&2; exit 2; }

required_symbols=(
  xray_ffi_version_major
  xray_ffi_version_minor
  xray_ffi_capabilities
  xray_core_cancel_tun_poll
  xray_tun_push_packets
  xray_tun_poll_packets
)
libraries=()
while IFS= read -r library; do
  libraries+=("$library")
done < <(find "$XCFRAMEWORK_PATH" -type f -name '*.a' -print)
[[ "${#libraries[@]}" -gt 0 ]] || { echo "XCFramework contains no static library slices" >&2; exit 2; }

for library in "${libraries[@]}"; do
  symbols="$(nm -g "$library" 2>/dev/null || true)"
  for symbol in "${required_symbols[@]}"; do
    if ! printf '%s\n' "$symbols" | awk -v expected="$symbol" \
      '$NF == expected || $NF == "_" expected { found = 1 } END { exit !found }'; then
      echo "slice is missing required ABI symbol $symbol: $library" >&2
      exit 1
    fi
  done
done

echo "apple_artifact_symbols=pass"

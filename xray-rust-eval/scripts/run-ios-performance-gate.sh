#!/usr/bin/env bash
set -euo pipefail

SOAK_SECONDS="${XRAY_FFI_SOAK_SECONDS:-1800}"
ALLOW_SHORT="${XRAY_ALLOW_SHORT_GATE:-0}"
if ! [[ "$SOAK_SECONDS" =~ ^[0-9]+$ ]] || [[ "$SOAK_SECONDS" -eq 0 ]]; then
  echo "XRAY_FFI_SOAK_SECONDS must be a positive integer" >&2
  exit 2
fi
if [[ "$SOAK_SECONDS" -lt 1800 && "$ALLOW_SHORT" != "1" ]]; then
  echo "release performance gate requires at least 1800 seconds; set XRAY_ALLOW_SHORT_GATE=1 only for local rehearsal" >&2
  exit 2
fi

if [[ "$SOAK_SECONDS" -ge 1800 ]]; then
  if [[ -z "${XRAY_FFI_CONFIG_PATH:-}" || ! -f "$XRAY_FFI_CONFIG_PATH" ]]; then
    echo "the 30-minute gate requires XRAY_FFI_CONFIG_PATH for a controlled service configuration" >&2
    exit 2
  fi
fi

REQUIRE_ZERO_DROPS="${XRAY_FFI_REQUIRE_ZERO_DROPS:-0}"
if [[ "$SOAK_SECONDS" -ge 1800 ]]; then
  REQUIRE_ZERO_DROPS=1
fi

XRAY_FFI_SOAK_SECONDS="$SOAK_SECONDS" \
XRAY_FFI_REQUIRE_ZERO_DROPS="$REQUIRE_ZERO_DROPS" \
XRAY_FFI_CONFIG_PATH="${XRAY_FFI_CONFIG_PATH:-}" \
  cargo test --release -p xray-ffi --test performance_and_soak_tests -- \
  --ignored --nocapture

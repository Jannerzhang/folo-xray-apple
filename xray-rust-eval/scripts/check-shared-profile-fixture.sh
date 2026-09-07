#!/usr/bin/env bash
set -euo pipefail

CORE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="${1:?usage: check-shared-profile-fixture.sh /path/to/folo-ios-core-eval}"
APP_FIXTURE="$APP_ROOT/Tests/FoloPacketTunnelTests/Resources/shared_vless_reality_golden.json"
CORE_FIXTURE="$CORE_ROOT/crates/xray-config/tests/fixtures/shared_vless_reality_golden.json"

for fixture in "$APP_FIXTURE" "$CORE_FIXTURE"; do
  if [[ ! -f "$fixture" ]]; then
    echo "missing shared profile fixture: $fixture" >&2
    exit 1
  fi
done

if ! cmp -s "$APP_FIXTURE" "$CORE_FIXTURE"; then
  echo "App/Core profile fixtures differ" >&2
  diff -u "$APP_FIXTURE" "$CORE_FIXTURE" >&2 || true
  exit 1
fi

shasum -a 256 "$APP_FIXTURE"

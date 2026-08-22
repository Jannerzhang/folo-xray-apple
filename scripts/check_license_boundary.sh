#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

if rg -n -i 'GPL-3\.0|AGPL|LGPL|SSPL|BUSL|Commons Clause|sagernet/sing|sing-shadowsocks' upstream --glob '!**/README.md' --glob '!**/LICENSE'; then
  echo "forbidden license or module identifier found in upstream source" >&2
  exit 1
fi

ruby scripts/verify_upstream_lock.rb

GOTOOLCHAIN=local go test github.com/xtls/xray-core/main/distro/folo
GOTOOLCHAIN=local go test github.com/xtls/libxray/xray
GOTOOLCHAIN=local go test github.com/Jannerzhang/folo-xray-apple/apple-wrapper

for target in \
  github.com/Jannerzhang/folo-xray-apple/apple-wrapper \
  github.com/xtls/xray-core/main/distro/folo \
  github.com/xtls/libxray/xray
do
  report="$(GOTOOLCHAIN=local go run github.com/google/go-licenses@v1.6.0 report "$target")"
  if printf '%s\n' "$report" | rg -n -i 'GPL-3\.0|AGPL|LGPL|SSPL|BUSL|Commons Clause'; then
    echo "forbidden license reported for $target" >&2
    exit 1
  fi
done

echo "license_boundary=pass"

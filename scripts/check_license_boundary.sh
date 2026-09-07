#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

export PATH="/Users/liwanqing/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.4.darwin-arm64/bin:${PATH}"

search_pattern() {
  local pattern="$1"
  local target_dir="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -n -i "$pattern" "$target_dir" --glob '!**/README.md' --glob '!**/LICENSE'
  else
    grep -r -n -E -i "$pattern" "$target_dir" --exclude="README.md" --exclude="LICENSE" || true
  fi
}

if search_pattern 'GPL-3\.0|AGPL|LGPL|SSPL|BUSL|Commons Clause|sagernet/sing|sing-shadowsocks' upstream | grep -q .; then
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
  if printf '%s\n' "$report" | grep -n -E -i 'GPL-3\.0|AGPL|LGPL|SSPL|BUSL|Commons Clause'; then
    echo "forbidden license reported for $target" >&2
    exit 1
  fi
done

echo "license_boundary=pass"

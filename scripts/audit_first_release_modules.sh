#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

deps_file="$(mktemp -t folo-xray-deps.XXXXXX)"
trap 'rm -f "$deps_file"' EXIT

GOTOOLCHAIN=local go list -deps github.com/xtls/xray-core/main/distro/folo > "$deps_file"

required=(
  'github.com/xtls/xray-core/main/folojson'
  'github.com/xtls/xray-core/main/foloinbound'
  'github.com/xtls/xray-core/main/folotun'
  'github.com/xtls/xray-core/app/dispatcher'
  'github.com/xtls/xray-core/app/proxyman/outbound'
  'github.com/xtls/xray-core/app/stats'
  'github.com/xtls/xray-core/proxy/vless/outbound'
  'github.com/xtls/xray-core/transport/internet/tcp'
  'github.com/xtls/xray-core/transport/internet/reality'
)

for package in "${required[@]}"; do
  if ! grep -Fxq "$package" "$deps_file"; then
    echo "required package missing: $package" >&2
    exit 1
  fi
done

forbidden_patterns=(
  'github.com/xtls/xray-core/infra/conf'
  'github.com/xtls/xray-core/main/json'
  'github.com/xtls/xray-core/app/dns'
  'github.com/xtls/xray-core/app/log'
  'github.com/xtls/xray-core/app/metrics'
  'github.com/xtls/xray-core/app/observatory'
  'github.com/xtls/xray-core/app/policy'
  'github.com/xtls/xray-core/app/proxyman/inbound'
  'github.com/xtls/xray-core/app/proxyman/command'
  'github.com/xtls/xray-core/app/router'
  'github.com/xtls/xray-core/app/reverse'
  'github.com/xtls/xray-core/proxy/dokodemo'
  'github.com/xtls/xray-core/proxy/http'
  'github.com/xtls/xray-core/proxy/socks'
  'github.com/xtls/xray-core/proxy/trojan'
  'github.com/xtls/xray-core/proxy/vmess'
  'github.com/xtls/xray-core/transport/internet/domainsocket'
  'github.com/xtls/xray-core/transport/internet/grpc'
  'github.com/xtls/xray-core/transport/internet/http'
  'github.com/xtls/xray-core/transport/internet/httpupgrade'
  'github.com/xtls/xray-core/transport/internet/kcp'
  'github.com/xtls/xray-core/transport/internet/quic'
  'github.com/xtls/xray-core/transport/internet/splithttp'
  'github.com/xtls/xray-core/transport/internet/websocket'
  'github.com/xtls/xray-core/proxy/shadowsocks'
  'github.com/xtls/xray-core/proxy/wireguard'
)

for package in "${forbidden_patterns[@]}"; do
  if grep -Fxq "$package" "$deps_file"; then
    echo "forbidden first-release package linked: $package" >&2
    exit 1
  fi
done

echo "first_release_module_boundary=pass dependency_count=$(wc -l < "$deps_file" | tr -d ' ')"

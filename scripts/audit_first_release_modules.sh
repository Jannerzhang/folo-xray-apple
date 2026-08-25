#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

export PATH="/Users/liwanqing/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.4.darwin-arm64/bin:${PATH}"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

deps_file="$(mktemp -t folo-xray-deps.XXXXXX)"
wrapper_deps_file="$(mktemp -t folo-xray-wrapper-deps.XXXXXX)"
trap 'rm -f "$deps_file" "$wrapper_deps_file"' EXIT

GOTOOLCHAIN=local go list -deps github.com/xtls/xray-core/main/distro/folo > "$deps_file"
GOTOOLCHAIN=local go list -deps github.com/Jannerzhang/folo-xray-apple/apple-wrapper > "$wrapper_deps_file"

required=(
  'github.com/xtls/xray-core/main/folojson'
  'github.com/xtls/xray-core/main/foloinbound'
  'github.com/xtls/xray-core/main/folotun'
  'github.com/xtls/xray-core/app/dispatcher'
  'github.com/xtls/xray-core/app/proxyman/outbound'
  'github.com/xtls/xray-core/app/stats'
  'github.com/xtls/xray-core/proxy/vless/outbound'
  'github.com/xtls/xray-core/proxy/trojan'
  'github.com/xtls/xray-core/proxy/vmess/outbound'
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

for package in "github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet" "github.com/sagernet/gvisor/pkg/tcpip/stack"; do
  if ! grep -q "$package" "$wrapper_deps_file"; then
    echo "required gVisor package missing from Apple wrapper: $package" >&2
    exit 1
  fi
done

if grep -E -q 'gvisor.dev/gvisor/pkg/(rawfile|eventfd|tcpip/link/(fdbased|sharedmem|stopfd|tun|xdp))' "$wrapper_deps_file"; then
  echo "Linux-only gVisor package linked by Apple wrapper" >&2
  exit 1
fi

echo "gvisor_netstack_boundary=pass dependency_count=$(grep -c '^gvisor.dev/gvisor/' "$wrapper_deps_file" | tr -d ' ')"

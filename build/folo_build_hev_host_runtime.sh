#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: Apache-2.0
# Build and run the public Hev adopted-stream lifecycle fixture on macOS.
# This is a host-only integration check; it never signs, installs or opens a
# system tunnel descriptor.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HEV_ROOT="${REPO_ROOT}/third_party/hev-socks5-tunnel"

for command_name in clang ar libtool make; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'hev host build error: %s is required\n' "${command_name}" >&2
    exit 1
  }
done

[[ -d "${HEV_ROOT}/src/core" ]] || {
  printf 'hev host build error: missing locked Hev core source\n' >&2
  exit 1
}

host_root="$(mktemp -d "${TMPDIR:-/tmp}/folo-hev-host.XXXXXX")"
trap 'rm -rf "${host_root}"' EXIT

common_cflags=(-O0 -g -Wall -Werror)
packetflow_cflags=(-DHEV_TUNNEL_PACKETFLOW)
yaml_version_cflags=(-DYAML_VERSION_MAJOR=0 -DYAML_VERSION_MINOR=2
                     -DYAML_VERSION_PATCH=5
                     '-DYAML_VERSION_STRING=\"0.2.5\"')
hev_include_flags=(
  "-I${HEV_ROOT}/src"
  "-I${HEV_ROOT}/src/misc"
  "-I${HEV_ROOT}/src/core/include"
  "-I${HEV_ROOT}/third-part/yaml/src"
  "-I${HEV_ROOT}/third-part/lwip/src/include"
  "-I${HEV_ROOT}/third-part/lwip/src/ports/include"
  "-I${HEV_ROOT}/third-part/hev-task-system/include"
  "-I${HEV_ROOT}/third-part/hev-task-system/src"
)

make -C "${HEV_ROOT}/third-part/hev-task-system" \
  CC=clang AR=ar \
  "CFLAGS=${common_cflags[*]}" \
  BINDIR="${host_root}/task/bin" BUILDDIR="${host_root}/task/build" static

make -C "${HEV_ROOT}/third-part/yaml" \
  CC=clang AR=ar \
  "CFLAGS=${common_cflags[*]} ${yaml_version_cflags[*]}" \
  BINDIR="${host_root}/yaml/bin" BUILDDIR="${host_root}/yaml/build" static

make -C "${HEV_ROOT}/third-part/lwip" \
  CC=clang AR=ar \
  "CFLAGS=${common_cflags[*]}" \
  BINDIR="${host_root}/lwip/bin" BUILDDIR="${host_root}/lwip/build" static

make -o tp-static -C "${HEV_ROOT}" \
  CC=clang AR=ar \
  "CFLAGS=${yaml_version_cflags[*]} ${packetflow_cflags[*]} ${common_cflags[*]} ${hev_include_flags[*]}" \
  BINDIR="${host_root}/hev/bin" BUILDDIR="${host_root}/hev/build" \
  THIRDPARTS= THIRDPARTDIR="${HEV_ROOT}/third-part" static

clang "${common_cflags[@]}" "${packetflow_cflags[@]}" \
  "${hev_include_flags[@]}" "-I${REPO_ROOT}/apple-wrapper/hev" \
  -c "${REPO_ROOT}/apple-wrapper/hev/folo_hev_packetflow.c" \
  -o "${host_root}/folo_hev_packetflow.o"

libtool -static -o "${host_root}/libFoloHevPacketFlow.a" \
  "${host_root}/folo_hev_packetflow.o" \
  "${host_root}/hev/bin/libhev-socks5-tunnel.a" \
  "${host_root}/task/bin/libhev-task-system.a" \
  "${host_root}/yaml/bin/libyaml.a" \
  "${host_root}/lwip/bin/liblwip.a"

clang "${common_cflags[@]}" "${packetflow_cflags[@]}" \
  "${hev_include_flags[@]}" "-I${REPO_ROOT}/apple-wrapper/hev" \
  "${REPO_ROOT}/build/folo_hev_host_runtime_fixture.c" \
  "${host_root}/libFoloHevPacketFlow.a" -lpthread \
  -o "${host_root}/folo-hev-host-runtime-fixture"

"${host_root}/folo-hev-host-runtime-fixture"

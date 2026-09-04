#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: Apache-2.0
# Build the independent MIT/BSD Hev evaluation closure for Apple arm64.
# This script deliberately excludes the upstream utun and Wintun backends.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HEV_ROOT="${REPO_ROOT}/third_party/hev-socks5-tunnel"
LOCK_FILE="${SCRIPT_DIR}/hev_toolchain.lock.yml"

die() {
  printf 'hev build error: %s\n' "$1" >&2
  exit 1
}

command -v xcrun >/dev/null 2>&1 || die "xcrun is required"
command -v xcodebuild >/dev/null 2>&1 || die "xcodebuild is required"
command -v clang >/dev/null 2>&1 || die "clang is required"
command -v ar >/dev/null 2>&1 || die "ar is required"
command -v ruby >/dev/null 2>&1 || die "ruby is required"
[[ -d "${HEV_ROOT}/src/core" ]] || die "missing locked Hev core source"
[[ -d "${HEV_ROOT}/third-part/hev-task-system" ]] || die "missing locked Hev task source"
[[ -d "${HEV_ROOT}/third-part/lwip" ]] || die "missing locked lwIP source"
[[ -d "${HEV_ROOT}/third-part/yaml" ]] || die "missing locked YAML source"
[[ ! -e "${HEV_ROOT}/src/hev-tunnel-macos.c" ]] || die "utun backend must not enter the evaluation tree"
[[ ! -e "${HEV_ROOT}/third-part/wintun" ]] || die "Wintun must not enter the evaluation tree"

lock_value() {
  ruby -ryaml -e 'data = YAML.load_file(ARGV[0]); value = ARGV[1].split(".").reduce(data) { |memo, key| memo.fetch(key) }; puts value' "${LOCK_FILE}" "$1"
}

source_tree_digest() {
  ruby -rdigest -e '
root = ARGV.fetch(0)
entries = Dir.glob(File.join(root, "**", "*"), File::FNM_DOTMATCH)
  .reject { |entry| entry.end_with?("/.") || entry.end_with?("/..") }
  .reject { |entry| File.directory?(entry) }
  .sort
lines = entries.map do |entry|
  relative = entry[(root.length + 1)..]
  stat = File.lstat(entry)
  digest = stat.symlink? ? Digest::SHA256.hexdigest(File.readlink(entry)) : Digest::SHA256.file(entry).hexdigest
  format("%o\t%s\t%s", stat.mode & 0o7777, relative, digest)
end
puts Digest::SHA256.hexdigest(lines.join("\n") + "\n")
' "${HEV_ROOT}"
}

EXPECTED_VENDOR_TREE="$(lock_value source.vendorTreeSha256)"
ACTUAL_VENDOR_TREE="$(source_tree_digest)"
[[ "${ACTUAL_VENDOR_TREE}" == "${EXPECTED_VENDOR_TREE}" ]] || die "vendored Hev tree ${ACTUAL_VENDOR_TREE} does not match ${EXPECTED_VENDOR_TREE}"

EXPECTED_XCODE="$(lock_value xcode.version)"
EXPECTED_XCODE_BUILD="$(lock_value xcode.build)"
EXPECTED_SDK="$(lock_value sdk.version)"
MIN_IOS="$(lock_value deploymentTarget)"
ACTUAL_XCODE="$(xcodebuild -version | awk 'NR == 1 {print $2}')"
ACTUAL_XCODE_BUILD="$(xcodebuild -version | awk 'NR == 2 {print $3}')"
ACTUAL_SDK="$(xcrun --sdk iphoneos --show-sdk-version)"
[[ "${ACTUAL_XCODE}" == "${EXPECTED_XCODE}" ]] || die "Xcode ${ACTUAL_XCODE} does not match ${EXPECTED_XCODE}"
[[ "${ACTUAL_XCODE_BUILD}" == "${EXPECTED_XCODE_BUILD}" ]] || die "Xcode build ${ACTUAL_XCODE_BUILD} does not match ${EXPECTED_XCODE_BUILD}"
[[ "${ACTUAL_SDK}" == "${EXPECTED_SDK}" ]] || die "iPhoneOS SDK ${ACTUAL_SDK} does not match ${EXPECTED_SDK}"

SOURCE_REVISION="$(lock_value source.candidate)"
BUILD_ROOT="${REPO_ROOT}/artifacts/hev/${SOURCE_REVISION}-${ACTUAL_VENDOR_TREE}"
SLICE_ROOT="${BUILD_ROOT}/ios-arm64"
rm -rf "${BUILD_ROOT}"
mkdir -p "${SLICE_ROOT}" "${BUILD_ROOT}/logs"
BUILD_LOG="${BUILD_ROOT}/logs/ios-arm64.log"
exec > >(tee "${BUILD_LOG}") 2>&1

SDK_PATH="$(xcrun --sdk iphoneos --show-sdk-path)"
CLANG="$(xcrun --sdk iphoneos --find clang)"
AR="$(xcrun --sdk iphoneos --find ar)"
COMMON_CFLAGS="-arch arm64 -isysroot ${SDK_PATH} -miphoneos-version-min=${MIN_IOS} -ffunction-sections -fdata-sections"

make -C "${HEV_ROOT}/third-part/hev-task-system" \
  CC="${CLANG}" AR="${AR}" \
  CFLAGS="${COMMON_CFLAGS}" \
  BINDIR="${SLICE_ROOT}/task/bin" BUILDDIR="${SLICE_ROOT}/task/build" static

make -C "${HEV_ROOT}/third-part/yaml" \
  CC="${CLANG}" AR="${AR}" \
  CFLAGS="${COMMON_CFLAGS}" \
  BINDIR="${SLICE_ROOT}/yaml/bin" BUILDDIR="${SLICE_ROOT}/yaml/build" static

make -C "${HEV_ROOT}/third-part/lwip" \
  CC="${CLANG}" AR="${AR}" \
  CFLAGS="${COMMON_CFLAGS}" \
  BINDIR="${SLICE_ROOT}/lwip/bin" BUILDDIR="${SLICE_ROOT}/lwip/build" static

HEV_INCLUDES=(
  "-I${HEV_ROOT}/src"
  "-I${HEV_ROOT}/src/misc"
  "-I${HEV_ROOT}/src/core/include"
  "-I${HEV_ROOT}/third-part/yaml/src"
  "-I${HEV_ROOT}/third-part/lwip/src/include"
  "-I${HEV_ROOT}/third-part/lwip/src/ports/include"
  "-I${HEV_ROOT}/third-part/hev-task-system/include"
  "-I${HEV_ROOT}/third-part/hev-task-system/src"
)
YAML_CFLAGS='-DYAML_VERSION_MAJOR=0 -DYAML_VERSION_MINOR=2 -DYAML_VERSION_PATCH=5 -DYAML_VERSION_STRING=\"0.2.5\"'
make -C "${HEV_ROOT}" \
  CC="${CLANG}" AR="${AR}" \
  CFLAGS="${YAML_CFLAGS} ${COMMON_CFLAGS} ${HEV_INCLUDES[*]}" \
  BINDIR="${SLICE_ROOT}/hev/bin" BUILDDIR="${SLICE_ROOT}/hev/build" \
  THIRDPARTS= \
  THIRDPARTDIR="${HEV_ROOT}/third-part" static

"${CLANG}" ${COMMON_CFLAGS} "${HEV_INCLUDES[@]}" \
  -I"${REPO_ROOT}/apple-wrapper" -c \
  "${REPO_ROOT}/apple-wrapper/folo_hev_packetflow.c" \
  -o "${SLICE_ROOT}/folo_hev_packetflow.o"

libtool -static -o "${SLICE_ROOT}/libFoloHevPacketFlow.a" \
  "${SLICE_ROOT}/folo_hev_packetflow.o" \
  "${SLICE_ROOT}/hev/bin/libhev-socks5-tunnel.a" \
  "${SLICE_ROOT}/task/bin/libhev-task-system.a" \
  "${SLICE_ROOT}/yaml/bin/libyaml.a" \
  "${SLICE_ROOT}/lwip/bin/liblwip.a"

cp "${REPO_ROOT}/apple-wrapper/folo_hev_packetflow.h" "${SLICE_ROOT}/folo_hev_packetflow.h"
file "${SLICE_ROOT}/libFoloHevPacketFlow.a" | tee "${BUILD_ROOT}/logs/file.txt"
nm -gU "${SLICE_ROOT}/libFoloHevPacketFlow.a" | awk '$3 ~ /^_FoloHevPacketFlow/ {print $3}' | sort -u | tee "${BUILD_ROOT}/symbols.txt"
grep -q '^_FoloHevPacketFlowStart$' "${BUILD_ROOT}/symbols.txt" || die "start symbol missing"
grep -q '^_FoloHevPacketFlowStop$' "${BUILD_ROOT}/symbols.txt" || die "stop symbol missing"
grep -q '^_FoloHevPacketFlowState$' "${BUILD_ROOT}/symbols.txt" || die "state symbol missing"

SOURCE_TREE_DIGEST="$(source_tree_digest)"
ARCHIVE_SHA256="$(shasum -a 256 "${SLICE_ROOT}/libFoloHevPacketFlow.a" | awk '{print $1}')"
ARCHIVE_BYTES="$(wc -c < "${SLICE_ROOT}/libFoloHevPacketFlow.a" | tr -d ' ')"
cat > "${BUILD_ROOT}/artifact-manifest.yml" <<EOF
schemaVersion: 1
artifact: libFoloHevPacketFlow.a
status: local-evaluation-only
source:
  repository: https://github.com/heiher/hev-socks5-tunnel
  revision: ${SOURCE_REVISION}
  vendorTreeSha256: ${SOURCE_TREE_DIGEST}
  patch: packetflow-backend-and-readiness-hooks
toolchain:
  xcode: ${ACTUAL_XCODE}
  xcodeBuild: ${ACTUAL_XCODE_BUILD}
  sdk: ${ACTUAL_SDK}
  deploymentTarget: "${MIN_IOS}"
target: arm64-apple-ios
symbols: symbols.txt
hashes:
  staticLibrary: ${ARCHIVE_SHA256}
sizes:
  staticLibraryBytes: ${ARCHIVE_BYTES}
license:
  audit: compliance/HEV_CANDIDATE_AUDIT_V1.yml
  approval: compliance/HEV_DEPENDENCY_APPROVAL_V1.yml
  notice: compliance/HEV_THIRD_PARTY_NOTICES.md
  manualReview: pending
integration:
  packetFlowBackend: public-adopted-stream
  utunBackend: excluded
  wintun: excluded
  xrayMPLSourceCopiedToPrivateClient: false
releaseReady: false
EOF
printf 'manifest=%s\n' "${BUILD_ROOT}/artifact-manifest.yml"

"${CLANG}" -arch arm64 -isysroot "${SDK_PATH}" \
  -miphoneos-version-min="${MIN_IOS}" \
  -I"${SLICE_ROOT}" -I"${REPO_ROOT}/apple-wrapper" \
  "${REPO_ROOT}/build/folo_hev_link_fixture.c" \
  "${SLICE_ROOT}/libFoloHevPacketFlow.a" -lpthread \
  -o "${BUILD_ROOT}/folo-hev-link-fixture"
file "${BUILD_ROOT}/folo-hev-link-fixture" | tee "${BUILD_ROOT}/logs/link-fixture-file.txt"
otool -l "${BUILD_ROOT}/folo-hev-link-fixture" | awk '
  /LC_BUILD_VERSION/ { found = 1 }
  found && /platform|minos|sdk/ { print }
  found && /sdk/ { exit }
' | tee "${BUILD_ROOT}/logs/link-fixture-build-version.txt"
grep -q 'platform 2' "${BUILD_ROOT}/logs/link-fixture-build-version.txt" || die "link fixture is not an iOS Mach-O"

printf 'hev_apple_build=pass source=%s xcode=%s sdk=%s artifact=%s\n' \
  "${SOURCE_REVISION}" "${ACTUAL_XCODE} (${ACTUAL_XCODE_BUILD})" "${ACTUAL_SDK}" "${SLICE_ROOT}/libFoloHevPacketFlow.a"

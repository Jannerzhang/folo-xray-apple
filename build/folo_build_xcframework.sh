#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: MPL-2.0
# Build only the public Apple ABI. The script intentionally does not call the
# upstream libXray build helper because that helper regenerates go.mod/go.sum
# from floating module state.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCK_FILE="${REPO_ROOT}/build/toolchain.lock.yml"

export PATH="/Users/liwanqing/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.4.darwin-arm64/bin:${PATH}"

die() {
  printf 'build error: %s\n' "$1" >&2
  exit 1
}

command -v go >/dev/null 2>&1 || die "go is required"
command -v xcodebuild >/dev/null 2>&1 || die "xcodebuild is required"
command -v xcrun >/dev/null 2>&1 || die "xcrun is required"
command -v file >/dev/null 2>&1 || die "file is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required to normalize the plist"
command -v ruby >/dev/null 2>&1 || die "ruby is required to read the lock file"

[[ -f "${LOCK_FILE}" ]] || die "missing ${LOCK_FILE}"
[[ -z "$(git -C "${REPO_ROOT}" status --porcelain)" ]] || die "worktree must be clean"

lock_value() {
  ruby -ryaml -e 'data = YAML.load_file(ARGV[0]); value = ARGV[1].split(".").reduce(data) { |memo, key| memo.fetch(key) }; puts value' "${LOCK_FILE}" "$1"
}

EXPECTED_GO="$(lock_value go.version)"
EXPECTED_XCODE="$(lock_value xcode.version)"
EXPECTED_XCODE_BUILD="$(lock_value xcode.build)"
EXPECTED_SDK="$(lock_value sdk.version)"
MIN_IOS="$(lock_value deploymentTarget)"

ACTUAL_GO="$(go version | awk '{print $3}')"
ACTUAL_XCODE="$(xcodebuild -version | awk 'NR == 1 {print $2}')"
ACTUAL_XCODE_BUILD="$(xcodebuild -version | awk 'NR == 2 {print $3}')"
ACTUAL_SDK="$(xcrun --sdk iphoneos --show-sdk-version)"

[[ "${ACTUAL_GO}" == "${EXPECTED_GO}" ]] || die "Go ${ACTUAL_GO} does not match ${EXPECTED_GO}"
[[ "${ACTUAL_XCODE}" == "${EXPECTED_XCODE}" ]] || die "Xcode ${ACTUAL_XCODE} does not match ${EXPECTED_XCODE}"
[[ "${ACTUAL_XCODE_BUILD}" == "${EXPECTED_XCODE_BUILD}" ]] || die "Xcode build ${ACTUAL_XCODE_BUILD} does not match ${EXPECTED_XCODE_BUILD}"
[[ "${ACTUAL_SDK}" == "${EXPECTED_SDK}" ]] || die "iPhoneOS SDK ${ACTUAL_SDK} does not match ${EXPECTED_SDK}"

SOURCE_REVISION="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
SOURCE_LOCK_SHA256="$(shasum -a 256 "${REPO_ROOT}/upstream.lock.yml" | awk '{print $1}')"
BUILD_ROOT="${REPO_ROOT}/artifacts/xcframework/${SOURCE_REVISION}"
SLICE_ROOT="${BUILD_ROOT}/slices"
HEADER_ROOT="${BUILD_ROOT}/headers"
FRAMEWORK_ROOT="${BUILD_ROOT}/FoloXray.xcframework"
BUILD_LOG="${BUILD_ROOT}/build.log"

rm -rf "${BUILD_ROOT}"
mkdir -p "${SLICE_ROOT}" "${HEADER_ROOT}"
exec > >(tee "${BUILD_LOG}") 2>&1

printf 'sourceRevision: %s\n' "${SOURCE_REVISION}"
printf 'sourceLockSha256: %s\n' "${SOURCE_LOCK_SHA256}"
printf 'go: %s\nxcode: %s (%s)\nsdk: %s\ndeploymentTarget: %s\n' "${ACTUAL_GO}" "${ACTUAL_XCODE}" "${ACTUAL_XCODE_BUILD}" "${ACTUAL_SDK}" "${MIN_IOS}"

"${REPO_ROOT}/scripts/audit_first_release_modules.sh" | tee "${BUILD_ROOT}/module-audit.txt"

build_slice() {
  local name="$1"
  local goos="$2"
  local goarch="$3"
  local sdk="$4"
  local arch="$5"
  local sdk_path
  local clang
  local clangxx
  local output_dir="${SLICE_ROOT}/${name}"
  local flags

  sdk_path="$(xcrun --sdk "${sdk}" --show-sdk-path)"
  clang="$(xcrun --sdk "${sdk}" --find clang)"
  clangxx="$(xcrun --sdk "${sdk}" --find clang++)"
  mkdir -p "${output_dir}"
  flags="-isysroot ${sdk_path} -m${sdk}-version-min=${MIN_IOS} -arch ${arch}"

  (
    cd "${REPO_ROOT}/apple-wrapper"
    env \
      PATH="${PATH}" \
      GOWORK="${REPO_ROOT}/go.work" \
      GOTOOLCHAIN=local \
      GOOS="${goos}" \
      GOARCH="${goarch}" \
      CGO_ENABLED=1 \
      GOFLAGS=-trimpath \
      CC="${clang}" \
      CXX="${clangxx}" \
      CGO_CFLAGS="${flags}" \
      CGO_CXXFLAGS="${flags}" \
      CGO_LDFLAGS="${flags} -Wl,-dead_strip" \
      "${GO_BIN:-go}" build \
        -buildmode=c-archive \
        -buildvcs=false \
        -ldflags='-s -w -buildid=' \
        -mod=readonly \
        -o "${output_dir}/libFoloXray.a" \
        .
  )
  ruby -e 'path = ARGV.fetch(0); bytes = File.binread(path); raise "not an ar archive" unless bytes.start_with?("!<arch>\n"); offset = 8; while offset < bytes.bytesize; raise "truncated ar header" if offset + 60 > bytes.bytesize; size = bytes.byteslice(offset + 48, 10).to_i; bytes[offset + 16, 12] = "0".ljust(12); offset += 60 + size; offset += 1 if offset.odd?; end; File.binwrite(path, bytes)' "${output_dir}/libFoloXray.a"
}

build_slice ios-arm64 ios arm64 iphoneos arm64
build_slice ios-simulator-arm64 ios arm64 iphonesimulator arm64
build_slice ios-simulator-x86_64 ios amd64 iphonesimulator x86_64

cp "${REPO_ROOT}/apple-wrapper/folo_apple.h" "${HEADER_ROOT}/folo_apple.h"
cp "${REPO_ROOT}/apple-wrapper/module.modulemap" "${HEADER_ROOT}/module.modulemap"

mkdir -p "${SLICE_ROOT}/ios-simulator"
lipo -create \
  "${SLICE_ROOT}/ios-simulator-arm64/libFoloXray.a" \
  "${SLICE_ROOT}/ios-simulator-x86_64/libFoloXray.a" \
  -output "${SLICE_ROOT}/ios-simulator/libFoloXray.a"

xcodebuild -create-xcframework \
  -library "${SLICE_ROOT}/ios-arm64/libFoloXray.a" -headers "${HEADER_ROOT}" \
  -library "${SLICE_ROOT}/ios-simulator/libFoloXray.a" -headers "${HEADER_ROOT}" \
  -output "${FRAMEWORK_ROOT}"

NOTICE_ROOT="${FRAMEWORK_ROOT}/ThirdPartyNotices"
mkdir -p "${NOTICE_ROOT}"
cp "${REPO_ROOT}/compliance/THIRD_PARTY_NOTICES.md" "${NOTICE_ROOT}/THIRD_PARTY_NOTICES.md"
cp "${REPO_ROOT}/compliance/gvisor-dependency-approval.yml" "${NOTICE_ROOT}/gvisor-dependency-approval.yml"

python3 - "${FRAMEWORK_ROOT}/Info.plist" <<'PY'
import plistlib
import sys

path = sys.argv[1]
with open(path, "rb") as handle:
    plist = plistlib.load(handle)
plist["AvailableLibraries"] = sorted(
    plist["AvailableLibraries"], key=lambda item: item["LibraryIdentifier"]
)
with open(path, "wb") as handle:
    plistlib.dump(plist, handle, fmt=plistlib.FMT_BINARY, sort_keys=True)
PY

FRAMEWORK_SLICE_DEVICE="${FRAMEWORK_ROOT}/ios-arm64/libFoloXray.a"
FRAMEWORK_SLICE_SIMULATOR="${FRAMEWORK_ROOT}/ios-arm64_x86_64-simulator/libFoloXray.a"
[[ -f "${FRAMEWORK_SLICE_DEVICE}" ]] || die "device slice missing from XCFramework"
[[ -f "${FRAMEWORK_SLICE_SIMULATOR}" ]] || die "simulator slice missing from XCFramework"

FIXTURE_ROOT="${BUILD_ROOT}/fixture"
mkdir -p "${FIXTURE_ROOT}"
xcrun --sdk iphonesimulator clang \
  -arch arm64 \
  -isysroot "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
  -miphonesimulator-version-min="${MIN_IOS}" \
  -I "${FRAMEWORK_ROOT}/ios-arm64_x86_64-simulator/Headers" \
  "${REPO_ROOT}/build/fixture/folo_xray_link_fixture.c" \
  "${FRAMEWORK_SLICE_SIMULATOR}" \
  -framework CoreFoundation \
  -framework Security \
  -lresolv \
  -o "${FIXTURE_ROOT}/FoloXrayLinkFixture"
file "${FIXTURE_ROOT}/FoloXrayLinkFixture" | tee "${FIXTURE_ROOT}/file.txt"
otool -l "${FIXTURE_ROOT}/FoloXrayLinkFixture" | awk '
  /LC_BUILD_VERSION/ { found = 1 }
  found && /platform|minos|sdk/ { print }
  found && /sdk/ { exit }
' | tee "${FIXTURE_ROOT}/build-version.txt"
grep -q 'minos 17\.0' "${FIXTURE_ROOT}/build-version.txt" || die "link fixture deployment target is not iOS 17.0"

mkdir -p "${BUILD_ROOT}/symbols"
nm -gU "${FRAMEWORK_SLICE_DEVICE}" | awk '$3 ~ /^_FoloXray/ {print $3}' | sort -u > "${BUILD_ROOT}/symbols/device.txt"
nm -gU "${FRAMEWORK_SLICE_SIMULATOR}" | awk '$3 ~ /^_FoloXray/ {print $3}' | sort -u > "${BUILD_ROOT}/symbols/simulator.txt"
cat "${BUILD_ROOT}/symbols/device.txt" "${BUILD_ROOT}/symbols/simulator.txt" | sort -u > "${BUILD_ROOT}/symbols/exported.txt"

EXPECTED_SYMBOLS="${BUILD_ROOT}/symbols/expected.txt"
printf '%s\n' \
	_FoloXrayNetstackReadPacket \
	_FoloXrayNetstackStart \
	_FoloXrayNetstackStop \
	_FoloXrayNetstackWritePacket \
	_FoloXrayPacketBridgeCopyStatsJSON \
	_FoloXrayPacketBridgeStart \
	_FoloXrayPacketBridgeState \
	_FoloXrayPacketBridgeStop \
	_FoloXrayCopyLastError \
  _FoloXrayCopyStatsJSON \
  _FoloXrayCopyVersion \
  _FoloXrayFreeString \
  _FoloXrayLastErrorCode \
	_FoloXrayStartJSON \
	_FoloXrayState \
	_FoloXrayStop \
	_FoloXrayValidateConfigJSON | sort -u > "${EXPECTED_SYMBOLS}"
diff -u "${EXPECTED_SYMBOLS}" "${BUILD_ROOT}/symbols/exported.txt" || die "exported ABI differs from the allowlist"

DEVICE_SHA256="$(shasum -a 256 "${FRAMEWORK_SLICE_DEVICE}" | awk '{print $1}')"
SIMULATOR_SHA256="$(shasum -a 256 "${FRAMEWORK_SLICE_SIMULATOR}" | awk '{print $1}')"
DEVICE_BYTES="$(wc -c < "${FRAMEWORK_SLICE_DEVICE}" | tr -d ' ')"
SIMULATOR_BYTES="$(wc -c < "${FRAMEWORK_SLICE_SIMULATOR}" | tr -d ' ')"
FRAMEWORK_SHA256="$(python3 - "${FRAMEWORK_ROOT}" <<'PY'
import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])
records = []
for path in sorted(item for item in root.rglob('*') if item.is_file()):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    records.append(f"{path.relative_to(root).as_posix()}  {digest}\n".encode())
print(hashlib.sha256(b"".join(records)).hexdigest())
PY
)"

cat > "${BUILD_ROOT}/artifact-manifest.yml" <<EOF
schemaVersion: 1
artifact: FoloXray.xcframework
source:
  repository: https://github.com/Jannerzhang/folo-xray-apple
  revision: ${SOURCE_REVISION}
  localOnly: true
  upstreamLockSha256: ${SOURCE_LOCK_SHA256}
toolchain:
  go: ${ACTUAL_GO}
  xcode: ${ACTUAL_XCODE}
  xcodeBuild: ${ACTUAL_XCODE_BUILD}
  sdk: ${ACTUAL_SDK}
  deploymentTarget: "${MIN_IOS}"
slices:
  - ios-arm64
  - ios-arm64_x86_64-simulator
moduleBoundary: module-audit.txt
distroProfile: compliance/distro-v1.yml
tuningProfile: compliance/mobile-tuning-v1.yml
symbols: symbols/exported.txt
thirdPartyNotices:
  - ThirdPartyNotices/THIRD_PARTY_NOTICES.md
  - ThirdPartyNotices/gvisor-dependency-approval.yml
sizes:
  deviceStaticLibraryBytes: ${DEVICE_BYTES}
  simulatorStaticLibraryBytes: ${SIMULATOR_BYTES}
hashes:
  deviceStaticLibrary: ${DEVICE_SHA256}
  simulatorStaticLibrary: ${SIMULATOR_SHA256}
  normalizedXcframework: ${FRAMEWORK_SHA256}
licenseBoundary: scripts/check_license_boundary.sh
sourceOffer: compliance/SOURCE_OFFER.md
linkFrameworks:
  - CoreFoundation
  - Security
  - libresolv
releaseReady: false
EOF

printf 'artifact: %s\n' "${FRAMEWORK_ROOT}"
printf 'manifest: %s/artifact-manifest.yml\n' "${BUILD_ROOT}"

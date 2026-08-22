#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: MPL-2.0
# Build only the public Apple ABI. The script intentionally does not call the
# upstream libXray build helper because that helper regenerates go.mod/go.sum
# from floating module state.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCK_FILE="${REPO_ROOT}/build/toolchain.lock.yml"

die() {
  printf 'build error: %s\n' "$1" >&2
  exit 1
}

command -v go >/dev/null 2>&1 || die "go is required"
command -v xcodebuild >/dev/null 2>&1 || die "xcodebuild is required"
command -v xcrun >/dev/null 2>&1 || die "xcrun is required"
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
      go build \
        -buildmode=c-archive \
        -buildvcs=false \
        -ldflags='-s -w -buildid=' \
        -mod=readonly \
        -o "${output_dir}/libFoloXray.a" \
        .
  )
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

FRAMEWORK_SLICE_DEVICE="${FRAMEWORK_ROOT}/ios-arm64/libFoloXray.a"
FRAMEWORK_SLICE_SIMULATOR="${FRAMEWORK_ROOT}/ios-arm64_x86_64-simulator/libFoloXray.a"
[[ -f "${FRAMEWORK_SLICE_DEVICE}" ]] || die "device slice missing from XCFramework"
[[ -f "${FRAMEWORK_SLICE_SIMULATOR}" ]] || die "simulator slice missing from XCFramework"

mkdir -p "${BUILD_ROOT}/symbols"
nm -gU "${FRAMEWORK_SLICE_DEVICE}" | awk '$3 ~ /^_FoloXray/ {print $3}' | sort -u > "${BUILD_ROOT}/symbols/device.txt"
nm -gU "${FRAMEWORK_SLICE_SIMULATOR}" | awk '$3 ~ /^_FoloXray/ {print $3}' | sort -u > "${BUILD_ROOT}/symbols/simulator.txt"
cat "${BUILD_ROOT}/symbols/device.txt" "${BUILD_ROOT}/symbols/simulator.txt" | sort -u > "${BUILD_ROOT}/symbols/exported.txt"

EXPECTED_SYMBOLS="${BUILD_ROOT}/symbols/expected.txt"
printf '%s\n' \
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
FRAMEWORK_SHA256="$(find "${FRAMEWORK_ROOT}" -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')"

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
symbols: symbols/exported.txt
hashes:
  deviceStaticLibrary: ${DEVICE_SHA256}
  simulatorStaticLibrary: ${SIMULATOR_SHA256}
  normalizedXcframework: ${FRAMEWORK_SHA256}
licenseBoundary: scripts/check_license_boundary.sh
sourceOffer: compliance/SOURCE_OFFER.md
releaseReady: false
EOF

printf 'artifact: %s\n' "${FRAMEWORK_ROOT}"
printf 'manifest: %s/artifact-manifest.yml\n' "${BUILD_ROOT}"

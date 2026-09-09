#!/usr/bin/env bash
set -euo pipefail

# SPDX-License-Identifier: Apache-2.0

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
SOURCE_ROOT="$REPO_ROOT/xray-rust-eval"
RUST_TOOLCHAIN="${FOLO_XRAY_RUST_TOOLCHAIN:-1.96.0}"
IOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD)"
ARTIFACT_DIR="${FOLO_XRAY_RUST_ARTIFACT_DIR:-$REPO_ROOT/artifacts/xcframework/$REVISION}"
CARGO_TARGET_DIR="${FOLO_XRAY_RUST_CARGO_TARGET_DIR:-$REPO_ROOT/.build/xray-rust-cargo}"
XCFRAMEWORK="$ARTIFACT_DIR/XrayRust.xcframework"

DEVICE_TARGET="aarch64-apple-ios"
SIM_ARM64_TARGET="aarch64-apple-ios-sim"
SIM_X86_TARGET="x86_64-apple-ios"
LIB_NAME="libxray_ffi.a"
HEADER_ROOT="$SOURCE_ROOT/crates/xray-ffi/include"

die() {
  printf 'rust_xcframework_build=fail: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

require_command cargo
require_command rustup
require_command xcodebuild
require_command lipo
require_command ruby

[[ -f "$SOURCE_ROOT/Cargo.toml" ]] || die "Rust source checkout is missing"
[[ -f "$HEADER_ROOT/xray_ffi.h" ]] || die "Rust FFI header is missing"
[[ -f "$HEADER_ROOT/module.modulemap" ]] || die "Rust FFI module map is missing"

for target in "$DEVICE_TARGET" "$SIM_ARM64_TARGET" "$SIM_X86_TARGET"; do
  rustup target list --installed | grep -Fxq "$target" || die "Rust target is not installed: $target"
done

mkdir -p "$ARTIFACT_DIR" "$CARGO_TARGET_DIR"
rm -rf -- "$XCFRAMEWORK"

build_target() {
  local target="$1"
  IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET" \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    cargo "+$RUST_TOOLCHAIN" build \
      --manifest-path "$SOURCE_ROOT/Cargo.toml" \
      --locked \
      --package xray-ffi \
      --release \
      --target "$target"
}

build_target "$DEVICE_TARGET"
build_target "$SIM_ARM64_TARGET"
build_target "$SIM_X86_TARGET"

DEVICE_LIB="$CARGO_TARGET_DIR/$DEVICE_TARGET/release/$LIB_NAME"
SIM_ARM64_LIB="$CARGO_TARGET_DIR/$SIM_ARM64_TARGET/release/$LIB_NAME"
SIM_X86_LIB="$CARGO_TARGET_DIR/$SIM_X86_TARGET/release/$LIB_NAME"
SIM_LIB="$ARTIFACT_DIR/simulator/libxray_ffi.a"

for library in "$DEVICE_LIB" "$SIM_ARM64_LIB" "$SIM_X86_LIB"; do
  [[ -f "$library" ]] || die "Rust static library is missing: $library"
done

mkdir -p "$(dirname "$SIM_LIB")"
lipo -create "$SIM_ARM64_LIB" "$SIM_X86_LIB" -output "$SIM_LIB"
xcodebuild -create-xcframework \
  -library "$DEVICE_LIB" -headers "$HEADER_ROOT" \
  -library "$SIM_LIB" -headers "$HEADER_ROOT" \
  -output "$XCFRAMEWORK"

REQUIRED_ABI_SYMBOLS=(
  xray_ffi_version_major
  xray_ffi_version_minor
  xray_ffi_capabilities
  xray_core_new
  xray_core_load_config_json
  xray_core_set_tun_runtime_profile
  xray_core_start
  xray_core_cancel_tun_poll
  xray_core_stop
  xray_core_free
  xray_error_code
  xray_error_message
  xray_error_free
  xray_tun_push_packet
  xray_tun_push_packets
  xray_tun_poll_packet
  xray_tun_poll_packets
  xray_tun_stats
)

verify_linked_symbols() {
  local sdk="$1"
  local arch="$2"
  local library="$3"
  local temp_dir
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/folo-rust-link.XXXXXX")"
  cat > "$temp_dir/main.c" <<'EOF'
#include "xray_ffi.h"
int main(void) {
  return (int)xray_ffi_version_major();
}
EOF
  xcrun --sdk "$sdk" clang \
    -arch "$arch" \
    -isysroot "$(xcrun --sdk "$sdk" --show-sdk-path)" \
    -m${sdk}-version-min="$IOS_DEPLOYMENT_TARGET" \
    -I "$HEADER_ROOT" \
    "$temp_dir/main.c" -Wl,-force_load,"$library" \
    -framework CoreFoundation -framework Security -lresolv \
    -o "$temp_dir/link"
  local symbols
  symbols="$(nm -gU "$temp_dir/link")"
  local symbol
  for symbol in "${REQUIRED_ABI_SYMBOLS[@]}"; do
    printf '%s\n' "$symbols" | awk -v expected="$symbol" \
      '$NF == expected || $NF == "_" expected { found = 1 } END { exit !found }' \
      || die "linked $sdk/$arch fixture is missing ABI symbol $symbol"
  done
  rm -rf -- "$temp_dir"
}

verify_linked_symbols iphoneos arm64 "$XCFRAMEWORK/ios-arm64/$LIB_NAME"
verify_linked_symbols iphonesimulator arm64 "$XCFRAMEWORK/ios-arm64_x86_64-simulator/$LIB_NAME"

rm -rf -- "$(dirname "$SIM_LIB")"

ruby "$REPO_ROOT/scripts/verify_rust_apple_artifact.rb" --artifact "$XCFRAMEWORK"

DEVICE_SHA256="$(shasum -a 256 "$XCFRAMEWORK/ios-arm64/$LIB_NAME" | awk '{print $1}')"
SIMULATOR_SHA256="$(shasum -a 256 "$XCFRAMEWORK/ios-arm64_x86_64-simulator/$LIB_NAME" | awk '{print $1}')"
FRAMEWORK_SHA256="$(ruby -rdigest -e 'root = ARGV.fetch(0); records = Dir.glob(File.join(root, "**", "*")).select { |path| File.file?(path) }.sort.map { |path| "#{path.delete_prefix(root + "/")}  #{Digest::SHA256.file(path).hexdigest}\n" }; puts Digest::SHA256.hexdigest(records.join)' "$XCFRAMEWORK")"
HEADER_SHA256="$(shasum -a 256 "$HEADER_ROOT/xray_ffi.h" | awk '{print $1}')"
MODULEMAP_SHA256="$(shasum -a 256 "$HEADER_ROOT/module.modulemap" | awk '{print $1}')"

cat > "$ARTIFACT_DIR/artifact-manifest.yml" <<EOF
# SPDX-License-Identifier: Apache-2.0
schemaVersion: 2
status: LOCAL_ONLY
artifact: XrayRust.xcframework
source:
  repository: https://github.com/Jannerzhang/folo-xray-apple
  revision: $REVISION
  rustTree: $(git -C "$REPO_ROOT" rev-parse "$REVISION:xray-rust-eval")
  sourcePath: xray-rust-eval
  rustToolchain: $RUST_TOOLCHAIN
  cargoLockSha256: $(shasum -a 256 "$SOURCE_ROOT/Cargo.lock" | awk '{print $1}')
  ffiHeaderSha256: $HEADER_SHA256
  moduleMapSha256: $MODULEMAP_SHA256
  abiMajor: 2
  abiMinor: 1
slices:
  - ios-arm64
  - ios-arm64_x86_64-simulator
hashes:
  deviceStaticLibrary: $DEVICE_SHA256
  simulatorStaticLibrary: $SIMULATOR_SHA256
  normalizedXcframework: $FRAMEWORK_SHA256
releaseReady: false
EOF

printf 'rust_xcframework_build=pass\n'
printf 'rust_xcframework_path=%s\n' "$XCFRAMEWORK"
printf 'rust_core_revision=%s\n' "$REVISION"

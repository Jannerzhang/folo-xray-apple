#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
core_root="$(cd -- "$script_dir/.." && pwd)"
source_root="$core_root/xray-rust-eval"
target_dir="${XRAY_RUST_EVAL_TARGET_DIR:-$core_root/.build/xray-rust-target}"
cargo_home="${XRAY_RUST_EVAL_CARGO_HOME:-$core_root/.build/xray-rust-cargo-home}"

if [[ ! -f "$source_root/Cargo.toml" ]]; then
  echo "xray_rust_build=fail: source checkout missing" >&2
  exit 1
fi

if ! rustup toolchain list | awk '$1 ~ /^1\.96\.0([.-]|$)/ { found = 1 } END { exit(found ? 0 : 1) }'; then
  echo "xray_rust_build=blocked: rustc 1.96.0 is not installed" >&2
  echo "required_toolchain=1.96.0"
  echo "observed_toolchain=$(rustc --version)"
  exit 2
fi
if ! rustc_196="$(rustc +1.96.0 --version 2>/dev/null)"; then
  echo "xray_rust_build=blocked: rustc 1.96.0 cannot be invoked" >&2
  exit 2
fi
[[ "$rustc_196" == "rustc 1.96.0 "* ]] || {
  echo "xray_rust_build=fail: unexpected pinned toolchain output" >&2
  exit 1
}

mkdir -p "$target_dir" "$cargo_home"
echo "xray_rust_toolchain=$rustc_196"
echo "xray_rust_target_dir=$target_dir"
echo "xray_rust_cargo_home=$cargo_home"
env CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target_dir" \
  cargo +1.96.0 test \
  --manifest-path "$source_root/Cargo.toml" \
  --locked --workspace --exclude xray-rust-fuzz --all-targets -- --test-threads=4
env CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target_dir" \
  IPHONEOS_DEPLOYMENT_TARGET=17.0 \
  CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS="-C link-arg=-miphoneos-version-min=17.0" \
  cargo +1.96.0 build \
  --manifest-path "$source_root/Cargo.toml" \
  --locked -p xray-ffi --target aarch64-apple-ios --release
echo "xray_rust_build=pass"

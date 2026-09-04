#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
core_root="$(cd -- "$script_dir/.." && pwd)"
source_root="$core_root/xray-rust-eval"

if [[ ! -f "$source_root/rust-toolchain.toml" ]]; then
  echo "xray_rust_apple_inputs=fail: source toolchain manifest missing" >&2
  exit 1
fi

if ! rustup toolchain list | awk '$1 ~ /^1\.96\.0([.-]|$)/ { found = 1 } END { exit(found ? 0 : 1) }'; then
  echo "xray_rust_apple_inputs=blocked: required rustc 1.96.0 is not installed"
  exit 2
fi

if ! "$source_root/scripts/check-mobile-toolchains.sh" --apple; then
  echo "xray_rust_apple_inputs=blocked: Apple target matrix is incomplete"
  exit 2
fi

echo "xray_rust_apple_inputs=pass"

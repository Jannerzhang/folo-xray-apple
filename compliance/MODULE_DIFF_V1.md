# Rust Core module boundary

状态：`rust-only`。当前 Apple 产物来自 `xray-rust-eval/crates/xray-ffi`。

## Active closure

- Rust `xray-ffi` ABI v2。
- Rust configuration, routing, transport, TUN and runtime crates required by
  the locked `xray-ffi` target graph。
- Apple static-library slices for iOS device and simulator only.

## Retired closure

- Go/cgo Apple wrapper and `FoloXray*` ABI。
- Go workspace, embedded Xray-core/libXray source and gVisor netstack。
- ABI-1 `xray-rust-mobile` evaluation package。
- POSIX socketpair bridge and private utun descriptor discovery wrappers。

The source lock, Cargo.lock, SBOM, ABI header, module map and artifact manifest
must be regenerated together whenever the active Rust closure changes.

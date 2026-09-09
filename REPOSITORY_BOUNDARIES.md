# Repository boundaries

## Allowed

- The locked Rust `xray-rust-eval` source and its MPL-2.0 modifications.
- Rust FFI headers, Apple static-library build scripts, SBOMs, notices and
  source-lock/release manifests.
- Synthetic fixtures and test-only Go oracle tools that never enter the Apple
  runtime or release artifact.

## Prohibited

- Folo UI, account, payment, entitlement, location, private backend or user
  data.
- Go/cgo runtime wrappers, gVisor netstack, generic local proxy listeners,
  private Apple APIs, raw credentials and private tunnel profiles.
- Prebuilt binaries without an immutable Rust source tag, ABI evidence, SBOM,
  notices and verified hashes.
- Floating Rust branches or unreviewed transitive dependencies.

## Interface boundary

The public artifact exposes only the reviewed Rust `xray_ffi` ABI v2. The
private iOS repository owns `NEPacketTunnelFlow`, profile handoff, signing,
Network Extension entitlements and user-facing lifecycle. A source or artifact
failure is fail-closed; the retired Go runtime is not a fallback.

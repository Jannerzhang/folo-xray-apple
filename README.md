# Folo Rust Core

Public provenance, reproducible-build and release repository for the Rust core
consumed by the Folo iOS Packet Tunnel Extension.

## Repository status

The active Apple runtime is the Rust `xray-rust-eval` workspace and its
`xray_ffi` ABI v2. The old Go/cgo Apple wrapper, gVisor netstack, Go workspace,
and ABI-1 mobile SDK evaluation have been retired from the active tree.

The Go sources under `xray-rust-eval` are test-only oracle tools used to pin
selected ClientHello and wire fixtures. They are never linked into the Rust
core, Apple XCFramework, or release artifact.

## Layout

```text
xray-rust-eval/  Rust core, xray_ffi ABI, tests and test-only oracles
build/           Rust Apple artifact build and evaluation records
compliance/      Rust source lock, SBOM, notices and release manifests
scripts/         Rust boundary, provenance and release verification
```

The private iOS repository owns Swift product code, Network Extension
lifecycle, profile handoff, entitlements and signing. This repository owns
only the public Rust core and its reproducible Apple artifact.

## Build

Install Rust `1.96.0` and the iOS targets, then run:

```sh
./build/build_rust_xcframework.sh
```

The output is an unsigned `XrayRust.xcframework` containing the iOS device and
simulator slices. It is checked for ABI v2 symbols, header/module-map hashes,
and source-tree identity before being accepted.

Rust FFI tests run with:

```sh
cargo test --manifest-path xray-rust-eval/Cargo.toml --locked -p xray-ffi --all-targets
```

The Go oracle fixture check is separate and test-only:

```sh
xray-rust-eval/scripts/verify-oracle-fixtures.sh
```

## Release boundary

Rust release tags use `rustX.Y`. A protected release job builds
`XrayRust.xcframework.zip`, generates the source-bound manifest/SBOM/notices,
signs the archive, and publishes all records together. A missing source lock,
ABI mismatch, unknown dependency, or unverified artifact blocks release.

See [REPOSITORY_BOUNDARIES.md](./REPOSITORY_BOUNDARIES.md),
[LICENSING.md](./LICENSING.md), and
[docs/2026-09-09-rust-core-retire-go-plan.md](./docs/2026-09-09-rust-core-retire-go-plan.md).

# Third-party notices — Folo Rust Core

This release boundary covers the Rust `xray-rust-eval` workspace and the
`xray_ffi` Apple artifact. The exact dependency graph is recorded in
`xray-rust-dependency-sbom-v1.json`; the source, Cargo.lock, FFI header and
module map are pinned by `xray-rust-eval-source-lock.yml`.

The Rust core retains its upstream MPL-2.0 license and every dependency keeps
its upstream notice. Generated Apple artifacts must include this notice file,
the dependency SBOM, and the immutable Rust Core source offer.

The Go oracle under `xray-rust-eval/tools/reality-oracle` is a test-only
reference generator. It is not part of the Rust dependency graph or any Apple
XCFramework and is intentionally excluded from the release artifact.

Do not add a runtime dependency, wrapper, listener, or native adapter here
without updating the source lock, ABI contract, SBOM, license audit and
release manifest together.

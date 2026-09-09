# Rust Apple artifact boundary

`build/build_rust_xcframework.sh` is the only root-level Apple artifact entry
point. It builds the checked-in `xray-rust-eval` `xray-ffi` crate with Rust
1.96.0, creates the iOS device and simulator slices, and verifies the public
ABI v2 symbol set.

The build never invokes Go, cgo, a generic Xray wrapper, a local proxy
listener, or a gVisor netstack. Go remains available only inside the nested
Rust workspace's fixture-oracle checks.

Generated output is local-only and ignored:

```text
artifacts/xcframework/<core-commit>/XrayRust.xcframework/
artifacts/xcframework/<core-commit>/artifact-manifest.yml
```

Release automation additionally packages the framework, Rust dependency SBOM,
third-party notices, source lock and RSA-SHA256 signature. No release is ready
without a public immutable Rust Core tag and protected signing approval.

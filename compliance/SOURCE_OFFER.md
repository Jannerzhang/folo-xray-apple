# Folo Rust Core source offer

Every published Core artifact must identify an immutable `rustX.Y` tag in:

<https://github.com/Jannerzhang/folo-xray-apple>

The release bundle records:

1. the exact Core commit and `xray-rust-eval` tree;
2. `Cargo.lock`, FFI header and module-map hashes;
3. the Rust ABI major/minor and exported-symbol contract;
4. the `XrayRust.xcframework` SHA-256;
5. the dependency SBOM, notices and RSA-SHA256 signature.

Until the immutable tag, artifact and protected signing records are published,
the manifest remains `releaseReady: false` and the iOS client must not consume
an unverified build.

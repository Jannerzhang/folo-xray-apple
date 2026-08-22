# Reproducible build boundary

Stage 08 uses the checked-in cgo recipe:

```shell
build/folo_build_xcframework.sh
```

The script requires the exact versions in `toolchain.lock.yml`, a clean
worktree, the committed `go.work`, and the public `apple-wrapper` ABI. It
produces an unsigned, local-only artifact under
`artifacts/xcframework/<source-revision>/`:

- `FoloXray.xcframework` with `ios-arm64` and
  `ios-arm64_x86_64-simulator` slices;
- `artifact-manifest.yml` with source, toolchain, symbols and hashes;
- `symbols/` and `build.log` for audit evidence.

Generated artifacts are ignored and are not committed to either the public
core repository or the private client repository. The artifact is not release
ready until the source-offer URL is public, the binary SBOM is attached, and
the later Packet Tunnel and device gates pass.

The build must resolve:

1. upstream/libXray against the sibling upstream/xray-core through the
   committed go.work and relative replacement;
2. the exact source and patch records in upstream.lock.yml;
3. no remote floating branch, private endpoint, signing key or node profile.

The upstream `build/main.py` helper is retained as source history but is not
used by Folo's release build because it regenerates module files from floating
state.

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
- `ThirdPartyNotices/` with the gVisor approval record and the checked-in
  third-party notice list used by the XCFramework bundle.

`fixture/folo_xray_link_fixture.c` is a minimal iOS 17 link fixture. It only
calls version and state functions and never starts the engine. The cgo archive
requires the system frameworks `CoreFoundation`, `Security`, and `libresolv`,
which are recorded in the artifact manifest and are not bundled third-party
code.

Stage 09 runs `scripts/audit_first_release_modules.sh` before compiling any
slice. The audit is tied to the Folo distro target rather than the full Xray
repository and records the dependency count plus required/forbidden package
paths in `module-audit.txt`. The build manifest also points to
`compliance/distro-v1.yml`, `compliance/mobile-tuning-v1.yml`, and records the
device/simulator static-library byte counts.

The first-release configuration is not generic Xray JSON. The public core
registers `main/folojson`, which accepts only the versioned VLESS/TCP/Reality
schema. `main/foloinbound` supplies the feature contract needed by Xray while
deliberately creating no TCP, UDP, or Unix listener. The Apple Packet Tunnel
owns the TUN/socket adapter and remains the only local traffic entry point.

Stage 10 adds `main/folotun` and the `FoloXrayPacketBridge*` ABI. This is a
bounded PacketFlow v1 framing/loopback endpoint for validating complete
IPv4/IPv6 packet transport over a public `SOCK_STREAM` socketpair. It does not
parse proxy protocols or create a listener; the private Swift bridge owns
`NEPacketTunnelFlow`, and the real VLESS/TUN data plane remains a later gate.
Stage 13 adds bounded `FoloXrayTCP*` and `FoloXrayUDP*` outbound transport
seams for a private MIT/Apache IP stack; these APIs do not add listeners or
generic configuration entry points.

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

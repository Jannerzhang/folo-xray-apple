# Hev PacketFlow v1 framing evidence

This is a local evaluation record for the public adopted-stream prototype. It
does not claim real proxy traffic, device success, distribution approval, or
completion of the later SOCKS/DNS stages.

## Cross-layer contract

The core `HEV_TUNNEL_PACKETFLOW` backend and the iOS
`HevPacketFlowEndpoint` use the same 12-byte, big-endian frame:

```text
FP | version=1 | family | protocol/next-header | reserved=0 |
uint32 packet length | reserved=0 | complete IP packet
```

Both sides use exact stream reads/writes. The core validates the declared
family, protocol, and IPv4/IPv6 length fields against the packet before
passing it to lwIP. The core has no Apple utun discovery path; the endpoint is
an explicitly adopted descriptor supplied by the caller.

## Checks

Core (`codex/hev-xray-core`, `556cc9a`) was built twice with:

```sh
bash build/folo_build_hev_apple.sh
```

Both runs exited `0`, produced an `arm64-apple-ios` archive, and linked the
fixture as `Mach-O 64-bit executable arm64` with `platform 2`, `minos 17.0`,
and `sdk 26.5`. The final archive was `676200` bytes with SHA-256:

```text
d9a3e5536a96216b6785b6003f8526dbce4c2b5e4fd668b5b068c6b588129ed0
```

The client (`codex/hev-xray-ios`, `074513c`) ran:

```sh
swift test --filter HevPacketFlowEndpointTests
```

Result: `2` tests passed, including a socketpair round trip with deliberately
partial frame writes and malformed-frame rejection. The related bounded queue
tests (`75f51df`) passed `4` tests.

Shutdown coverage at this stage is limited to endpoint close idempotence and
the link fixture's invalid-start/stop API checks. A running Hev session has not
been connected to a real `NEPacketTunnelFlow`, SOCKS proxy, or physical device.

## Host wrapper lifecycle recheck (2026-09-04)

Core commit `97c8a41` adds a reproducible host-only fixture and executes:

```sh
bash build/folo_build_hev_host_runtime.sh
```

Result:

```text
hev_host_runtime=pass start=running stop=idle owner=dup
```

The fixture builds the `HEV_TUNNEL_PACKETFLOW` closure in a temporary directory,
creates its own POSIX `SOCK_STREAM` socketpair, calls the public Hev wrapper with
the bounded staging configuration, checks the running/idle state transitions,
and verifies that the caller-owned descriptor remains valid before and after
stop. It does not open or inspect a system tunnel descriptor and does not claim
iOS device, SOCKS proxy, or real network traffic success.

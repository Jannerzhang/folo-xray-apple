# Apple wrapper boundary

This directory contains the small, public MPL-2.0 Apple ABI used by the
private Folo client. It may expose only the version/capability, create/start,
stop, status/statistics and controlled profile-loading boundary described in
REPOSITORY_BOUNDARIES.md.

No Folo account, subscription, entitlement, endpoint, node credential,
SwiftUI, StoreKit or product implementation may be added here. The actual
Packet Tunnel integration is a later stage and remains in the private
folo-ios repository.

## ABI contract

`folo_apple.h` is the only supported native boundary:

- `FoloXrayValidateConfigJSON` parses a bounded in-memory JSON profile;
- `FoloXrayStartJSON` starts one managed Xray instance from the same bounded
  byte buffer;
- `FoloXrayStop`, `FoloXrayState`, and `FoloXrayLastErrorCode` manage the
  lifecycle without exposing a command server or filesystem path;
- `FoloXrayCopyVersion`, `FoloXrayCopyLastError`, and
  `FoloXrayCopyStatsJSON` return caller-owned strings;
- every returned string must be released with `FoloXrayFreeString`.

The wrapper returns coarse, stable error messages. It does not return the
original configuration or upstream error text across the ABI. The current
stats surface reports lifecycle metadata and the two reserved first-release
traffic counter names; PacketFlow wiring and traffic counter registration are
implemented in later stages.

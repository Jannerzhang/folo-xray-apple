# Apple wrapper boundary

This directory is reserved for generic Apple-facing code. It may expose only
the version/capability, create/start, stop, status/statistics and controlled
profile-loading boundary described in REPOSITORY_BOUNDARIES.md.

No Folo account, subscription, entitlement, endpoint, node credential,
SwiftUI, StoreKit or product implementation may be added here. The actual
Packet Tunnel integration is a later stage and remains in the private
folo-ios repository.

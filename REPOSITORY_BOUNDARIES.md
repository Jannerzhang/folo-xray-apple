# Repository boundaries

## Allowed

- Locked Xray-core/libXray upstream source and provenance.
- Modifications to MPL-covered files.
- Generic Apple wrapper code required to expose the approved runtime API.
- Reproducible build scripts, patch series, SBOM, notices, source-offer instructions, symbol lists, and release manifests.
- Synthetic fixtures containing no Folo production data or credentials.

## Prohibited

- Folo UI, account, payment, entitlement, location, or private backend implementation.
- Production API endpoints, Apple signing material, node credentials, user data, or real tunnel profiles.
- FlClash, sing-box, or Mihomo source, tests, resources, configuration generators, or Git history.
- Prebuilt binaries without corresponding source tag, build instructions, SBOM, notices, and verified hashes.
- Floating upstream branches or unreviewed transitive dependencies.

## Interface boundary

The public artifact may expose only version/capability, create/start, stop, status/statistics, and controlled configuration-loading functions. It must not expose arbitrary command execution, a generic local proxy listener, or access to private Apple APIs.

The private App repository consumes a release manifest and verified artifact. It does not mirror this repository's MPL source.

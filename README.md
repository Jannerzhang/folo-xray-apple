# Folo Xray Apple

Public compliance and reproducible-build repository for the Xray runtime used by the Folo iOS Packet Tunnel Extension.

## Repository status

The repository begins empty. No upstream source or binary has been imported yet. A later approved stage will lock exact Xray-core and libXray commits, preserve upstream history and notices, apply a reviewable Apple patch series, and publish reproducible XCFramework evidence.

This repository must never contain Folo account logic, private API implementations, production endpoints, signing material, node credentials, user data, or proprietary SwiftUI product source.

## Planned layout

```text
upstream/       locked upstream source or documented acquisition inputs
patches/        ordered, reviewable patch series
apple-wrapper/  generic Apple runtime boundary
build/          reproducible build scripts
compliance/     licenses, SBOM, notices, source-offer and manifests
```

No directory is created until its stage has approved source and license inputs.

## Licensing

Each imported file retains its upstream license and copyright notice. MPL-2.0-covered modifications remain publicly available. Original wrapper/build files must declare an approved per-file license. See [LICENSING.md](./LICENSING.md).

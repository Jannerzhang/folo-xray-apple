# Folo Xray Apple

Public compliance and reproducible-build repository for the Xray runtime used by the Folo iOS Packet Tunnel Extension.

## Repository status

The local stage-07 baseline is now imported and locked. It uses Xray-core
v1.8.24 with libXray v3.1.0, applies a public GPL-free VLESS/Reality distro
patch, and has no XCFramework or release binary yet. The local repository has
not been pushed to the remote repository.

This repository must never contain Folo account logic, private API implementations, production endpoints, signing material, node credentials, user data, or proprietary SwiftUI product source.

## Layout

```text
upstream/       locked upstream source or documented acquisition inputs
patches/        ordered, reviewable patch series
apple-wrapper/  generic Apple runtime boundary
build/          reproducible build scripts
compliance/     licenses, SBOM, notices, source-offer and manifests
```

The source, patch, build, Apple boundary and compliance directories are
created only from approved inputs. Stage 08 is responsible for the first
reproducible XCFramework.

## Licensing

Each imported file retains its upstream license and copyright notice. MPL-2.0-covered modifications remain publicly available. Original wrapper/build files must declare an approved per-file license. See [LICENSING.md](./LICENSING.md).

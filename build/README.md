# Reproducible build boundary

Stage 07 records source inputs and the GPL-free first-release distro. Stage 08
will add the pinned Apple SDK/Go/gomobile or cgo recipe and produce the first
XCFramework. Until then, no generated framework or unsigned binary is a
release artifact.

The build must resolve:

1. upstream/libXray against the sibling upstream/xray-core through the
   committed go.work and relative replacement;
2. the exact source and patch records in upstream.lock.yml;
3. no remote floating branch, private endpoint, signing key or node profile.

# Third-party notices — local Xray Apple baseline

This notice describes the import closure scanned for:

- github.com/Jannerzhang/folo-xray-apple/apple-wrapper
- github.com/xtls/xray-core/main/distro/folo
- github.com/xtls/libxray/xray

The scan was run on 2026-08-23 with
github.com/google/go-licenses@v1.6.0. The exact upstream source and license
files are retained under upstream/; the lock, commit and license hashes are
in [upstream.lock.yml](../upstream.lock.yml). The wrapper's own MPL-2.0 text
is retained in [apple-wrapper/LICENSE](../apple-wrapper/LICENSE).

The stage-09 Folo production dependency audit reports 389 packages for the
`main/distro/folo` closure. It is intentionally narrower than the full Xray
source tree: `main/folojson` is the only mobile JSON loader and
`main/foloinbound` is an empty manager used to keep the Packet Tunnel as the
only local traffic entry point. See [MODULE_DIFF_V1.md](MODULE_DIFF_V1.md) and
[distro-v1.yml](distro-v1.yml) for the exact allow/deny boundary.

No GPL, AGPL, LGPL, SSPL, BUSL, non-commercial or no-derivatives component was
reported in the current import closure. This is a local baseline record, not
an assertion that an App Store release is ready: stage 08 must add the
XCFramework binary SBOM and exported-symbol audit.

| Component | Version / revision | SPDX | License/source record |
| --- | --- | --- | --- |
| Folo public Apple wrapper | local commit | MPL-2.0 | [apple-wrapper/LICENSE](../apple-wrapper/LICENSE) |
| Folo first-release JSON boundary | local commit | MPL-2.0 | [distro-v1.yml](distro-v1.yml) |
| Folo empty inbound manager | local commit | MPL-2.0 | [distro-v1.yml](distro-v1.yml) |
| Folo PacketFlow framing endpoint | local commit | MPL-2.0 | [upstream/xray-core/main/folotun](../upstream/xray-core/main/folotun) |
| XTLS/libXray | v3.1.0 | MIT | [upstream/libXray/LICENSE](../upstream/libXray/LICENSE) |
| XTLS/Xray-core | v1.8.24 | MPL-2.0 | [upstream/xray-core/LICENSE](../upstream/xray-core/LICENSE) |
| XTLS/reality | 48f0b2d5ed6d | MPL-2.0 | https://github.com/XTLS/reality/blob/48f0b2d5ed6d/LICENSE |
| cloudflare/circl | v1.4.0 | BSD-3-Clause | https://github.com/cloudflare/circl/blob/v1.4.0/LICENSE |
| cloudflare/circl/ecc/p384 | v1.4.0 | BSD-3-Clause | https://github.com/cloudflare/circl/blob/v1.4.0/ecc/p384/LICENSE |
| OmarTariq612/goech | 8e2e1dafd3a0 | MIT | https://github.com/OmarTariq612/goech/blob/8e2e1dafd3a0/LICENSE |
| andybalholm/brotli | v1.1.0 | MIT | https://github.com/andybalholm/brotli/blob/v1.1.0/LICENSE |
| dgryski/go-metro | adc40b04c140 | MIT | https://github.com/dgryski/go-metro/blob/adc40b04c140/LICENSE |
| francoispqt/gojay | v1.2.13 | MIT | https://github.com/francoispqt/gojay/blob/v1.2.13/LICENSE |
| ghodss/yaml | d8423dcdf344 | MIT | https://github.com/ghodss/yaml/blob/d8423dcdf344/LICENSE |
| gorilla/websocket | v1.5.3 | BSD-2-Clause | https://github.com/gorilla/websocket/blob/v1.5.3/LICENSE |
| klauspost/compress | v1.17.8 | Apache-2.0 | https://github.com/klauspost/compress/blob/v1.17.8/LICENSE |
| klauspost/compress/internal/snapref | v1.17.8 | BSD-3-Clause | https://github.com/klauspost/compress/blob/v1.17.8/internal/snapref/LICENSE |
| klauspost/compress/zstd/internal/xxhash | v1.17.8 | MIT | https://github.com/klauspost/compress/blob/v1.17.8/LICENSE.txt |
| klauspost/cpuid/v2 | v2.2.7 | MIT | https://github.com/klauspost/cpuid/blob/v2.2.7/LICENSE |
| pelletier/go-toml | v1.9.5 | Apache-2.0 | https://github.com/pelletier/go-toml/blob/v1.9.5/LICENSE |
| pires/go-proxyproto | v0.7.0 | Apache-2.0 | https://github.com/pires/go-proxyproto/blob/v0.7.0/LICENSE |
| quic-go/qpack | v0.4.0 | MIT | https://github.com/quic-go/qpack/blob/v0.4.0/LICENSE.md |
| quic-go/quic-go | v0.46.0 | MIT | https://github.com/quic-go/quic-go/blob/v0.46.0/LICENSE |
| refraction-networking/utls | v1.6.7 | BSD-3-Clause | https://github.com/refraction-networking/utls/blob/v1.6.7/LICENSE |
| refraction-networking/utls/dicttls | v1.6.7 | BSD-3-Clause | https://github.com/refraction-networking/utls/blob/v1.6.7/dicttls/LICENSE |
| riobard/go-bloom | cdc8013cb5b3 | Apache-2.0 | https://github.com/riobard/go-bloom/blob/cdc8013cb5b3/LICENSE |
| seiflotfy/cuckoofilter | a2f2c23f1771 | MIT | https://github.com/seiflotfy/cuckoofilter/blob/a2f2c23f1771/LICENSE |
| v2fly/ss-bloomring | 28617310f63e | Apache-2.0 | https://github.com/v2fly/ss-bloomring/blob/28617310f63e/LICENSE |
| go4.org/netipx | fdeea329fbba | BSD-3-Clause | https://github.com/go4org/netipx/blob/fdeea329fbba/LICENSE |
| golang.org/x/crypto | v0.26.0 | BSD-3-Clause | https://cs.opensource.google/go/x/crypto/+/v0.26.0:LICENSE |
| golang.org/x/exp | fd00a0e0eefc | BSD-3-Clause | https://cs.opensource.google/go/x/exp/+/fd00a0e0eefc:LICENSE |
| golang.org/x/net | v0.28.0 | BSD-3-Clause | https://cs.opensource.google/go/x/net/+/v0.28.0:LICENSE |
| golang.org/x/sys | v0.24.0 | BSD-3-Clause | https://cs.opensource.google/go/x/sys/+/v0.24.0:LICENSE |
| golang.org/x/text | v0.17.0 | BSD-3-Clause | https://cs.opensource.google/go/x/text/+/v0.17.0:LICENSE |
| google.golang.org/genproto/googleapis/rpc/status | ef581f913117 | Apache-2.0 | https://github.com/googleapis/go-genproto/blob/ef581f913117/googleapis/rpc/LICENSE |
| google.golang.org/grpc | v1.66.0 | Apache-2.0 | https://github.com/grpc/grpc-go/blob/v1.66.0/LICENSE |
| google.golang.org/protobuf | v1.34.2 | BSD-3-Clause | https://github.com/protocolbuffers/protobuf-go/blob/v1.34.2/LICENSE |
| gopkg.in/yaml.v2 | v2.4.0 | Apache-2.0 | https://github.com/go-yaml/yaml/blob/v2.4.0/LICENSE |
| gopkg.in/yaml.v3 | v3.0.1 | MIT | https://github.com/go-yaml/yaml/blob/v3.0.1/LICENSE |
| lukechampine.com/blake3 | v1.3.0 | MIT | https://github.com/lukechampine.com/blake3/blob/v1.3.0/LICENSE |

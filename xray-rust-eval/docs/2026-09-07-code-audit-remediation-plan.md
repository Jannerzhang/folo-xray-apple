# Code Audit Remediation Plan (2026-09-07)

## Objective

Implement the P0, P1, and P2 findings from the supplied audit conclusion as real build/data-plane fixes. The App and Core repositories use the following baselines:

- App: `/Users/liwanqing/Documents/UGit/folo-ios-core-eval` at `codex/xray-rust-core-eval`
- Core: `/Users/liwanqing/Documents/UGit/folo-xray-apple-core-eval` at `codex/xray-rust-core-eval`

Each remediation stage has a separate paired `codex/audit-fix-*` branch. Stage 01 is created directly from the two baselines. A dependent later stage is created from the same baseline and explicitly carries only verified prerequisite commits.

## Stages and branches

| Stage | Paired branch | Scope | Acceptance |
|---|---|---|---|
| 01 | `codex/audit-fix-01-license-gate` | Cargo graph, SBOM, license and toolchain gates | Cargo graph/lock/SBOM/source commit agree; without a real Rust artifact, `releaseReady=false` and `appIntegrationAllowed=false` |
| 02 | `codex/audit-fix-02-abi-artifact` | ABI allowlist, artifact manifest and App Xcode Sources | clean-checkout Packet Tunnel target build; every called symbol is gated |
| 03 | `codex/audit-fix-03-route-policy` | unified RoutePolicy, Swift→Go projection and Go/Rust precedence | production data plane consumes the full rule set and emits revision/action/reason/provenance |
| 04 | `codex/audit-fix-04-dns-cache` | revision/client-aware DNS attribution, NAT64/CNAME/LRU/budget | old generations cannot affect new flows; NAT64-only, refresh, CNAME-change and capacity tests |
| 05 | `codex/audit-fix-05-quic` | QUIC CRYPTO reassembly, flow state, fallback execution and metrics | failures actually select TCP fallback or explicit block; real VLESS Reality/XUDP remains an interop gate |
| 06 | `codex/audit-fix-06-lifecycle-diagnostics` | native wakeup, stop/join, generation tokens and diagnostics | stop/start, reconnect and network migration cannot leave an old loop processing a new session |
| 07 | `codex/audit-fix-07-hardening` | fingerprint, IP validation, feature gating, clippy, EOF and portable scripts | lint, diff, fresh-checkout scripts and fail-closed gates pass |

This plan does not declare Rust production stages 7/11 complete. No simulated, stale, or unverified artifact may be marked release-ready.

## Execution rules

1. Keep each stage's write set narrow and leave unrelated working-tree changes untouched.
2. Add a regression test or gate before the corresponding implementation where behavior is not already protected.
3. Run proportional Swift/Go/Rust/Xcode verification after each stage, then create a Chinese Lore commit and push that stage branch.
4. Keep the release gate fail-closed when real device, signing, remote service, or interop evidence is unavailable; do not replace missing evidence with a passing unit test.

## Compatibility and rollback

- The Go/gVisor path remains the safe default. The Rust candidate cannot be selected until artifact, ABI, license, device, and interop gates are all complete.
- Any graph, lock, SBOM, source revision, or symbol mismatch blocks integration.
- Each stage is reversible by reverting its stage commit; the two baseline branches are not rewritten.

## Final acceptance

- Both repositories are clean and every stage branch/commit has been pushed.
- Swift Package tests, Packet Tunnel clean target build when local inputs exist, Go test/vet/race, Rust test/clippy, and diff checks have recorded evidence.
- `releaseReady`, `appIntegrationAllowed`, device, and interop status match the evidence actually available.

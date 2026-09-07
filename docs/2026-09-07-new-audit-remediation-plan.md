# New stage 7–10 audit remediation plan

## Objective

Address `/Users/liwanqing/.codex/attachments/230f6ee7-0076-41bb-8032-fda83df8748e/pasted-text.txt` from the previous verified `codex/audit-fix-07-hardening` line: ABI/layout drift, batch partial-success semantics, cancellation barriers, unified byte budgets, fair scheduling, safe UDP eviction, real artifact gates, and meaningful stress/link verification.

## Stages

1. `codex/audit-fix-08-abi-batch`: single-source ABI version/layout/capability contract; bounded batch push with `(status, acceptedCount)` and suffix retry; complete symbol/link gates.
2. `codex/audit-fix-09-lifecycle-budget`: cancel → join → stop lifecycle barrier and byte-accounted bounded queues across UDP/TUN/events/DNS.
3. `codex/audit-fix-10-scheduler-lru`: per-flow packet/byte/time quantum, deferred queue and rotating cursor; idle/closed-only UDP eviction; strict batch quantum.
4. `codex/audit-fix-11-production-acceptance`: wire the Rust adapter into the production Packet Tunnel flavor, derive ABI size evidence, and run available stress/race/link acceptance checks.

## Acceptance

- Rust format, workspace Clippy with all targets/features, workspace tests, FFI layout/symbol/link checks, and Go test/vet pass.
- Swift full tests, clean Packet Tunnel target build, both Rust adapter slices, and real FFI input verification pass.
- Every stage is isolated, committed with Chinese Lore-style messages, and pushed to its matching remote branch.

## Compatibility and rollback

- Keep legacy single-packet wrappers for source compatibility; production batch callers must retry only the unaccepted suffix.
- Fail closed on all malformed/over-limit/lifecycle errors; never allocate from untrusted counts.
- Later branches stack only on verified earlier branches so each stage can be reverted independently.

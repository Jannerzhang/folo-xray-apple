# Licensing policy

This repository is a multi-license Rust source distribution. No repository-wide
license overrides the license of imported upstream files.

- `xray-rust-eval` retains its upstream MPL-2.0 notices and obligations.
- Cargo dependencies are locked and recorded in the Rust dependency SBOM.
- Unknown, GPL, AGPL, LGPL, SSPL, BUSL, non-commercial, no-derivatives,
  source-available restrictions, or unapproved custom licenses block release.
- The test-only Go oracle is not part of the Apple runtime or artifact; its
  fixture inputs remain under the applicable upstream notices.
- Original Rust build, boundary and compliance files use their declared SPDX
  identifiers.

Every client release must link to the exact public Rust Core tag and matching
artifact, SBOM, notice and source-lock evidence.

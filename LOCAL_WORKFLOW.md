# Local workflow

This repository is maintained locally before the public source baseline is published.

- `main` is the protected integration branch.
- Work must happen on a named topic branch.
- The local `.githooks/pre-commit` rejects commits made directly on `main`.
- The public GitHub `main-protection` Ruleset is already configured for `refs/heads/main`.
- Every upstream import, patch, artifact, SBOM, and notice requires review before publication.

Enable the local hook once per checkout:

```bash
git config core.hooksPath .githooks
```

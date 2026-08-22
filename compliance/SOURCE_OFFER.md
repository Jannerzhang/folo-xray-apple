# Folo Xray Apple source offer

## Current local-first status

The source baseline is intentionally local-only while the repository owner
reviews the first public commit. No remote push has been performed. The exact
local source is available at:

    /Users/barneszhang/Documents/UGit/folo-xray-apple

The intended public source URL, to be activated only after the owner publishes
the local main branch, is:

<https://github.com/Jannerzhang/folo-xray-apple>

Until that publication happens, no App Store build may claim that this source
offer is publicly reachable.

## Release mapping

Each App build must record:

1. the immutable app-v<app-version>-core.<revision> tag;
2. the corresponding upstream.lock.yml;
3. the applied patches/series.yml;
4. the XCFramework artifact SHA-256;
5. the generated SPDX SBOM and THIRD_PARTY_NOTICES.md.

The source offer must expose the exact public tag, all MPL-covered modified
files, the build instructions, license texts, dependency lock and artifact
hash. A newer core must use a new tag and must not rewrite an older release.

## Publication checklist

- [ ] Local main has the reviewed root and baseline commits.
- [ ] Public repository is non-empty and the exact commit is reachable.
- [ ] The public tag is immutable and maps to an App build manifest.
- [ ] MPL source, patch series, notices and build recipe are downloadable.
- [ ] The App's license screen links to the exact tag.

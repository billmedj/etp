# Source provenance

## Initial repository history

This repository is a sanitized extraction from a larger local development
worktree. The extracted ETP files did not have a separate Git history. The
initial commit in this repository is therefore the first authoritative ETP
source snapshot.

The larger worktree had base commit
`ff1be2d9cd245d1b02346ac5017ae479492d4a61` when the extraction started. The
ETP source was untracked in that worktree. The base commit does not identify or
authenticate the extracted ETP content.

The extraction excludes product-specific adapters, product documentation,
private research material, local build output, credentials, logs, and user
data.

## Maintainer responsibility

The maintainer reviewed and selected the source included in the initial
snapshot. Development tools, including AI-assisted tools, do not own or approve
the result. Human contributors remain responsible for licensing,
confidentiality, testing, and submitted changes.

## Release provenance

A release must identify:

- the source commit;
- the version tag;
- the build workflow and pinned tool versions;
- generated artifacts and their SHA-256 digests;
- the tests and formal checks that ran;
- the dependency inventory for each binary artifact.

See [the release checklist](./.github/RELEASE_CHECKLIST.md).

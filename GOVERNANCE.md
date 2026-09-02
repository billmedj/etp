# ETP governance

ETP uses maintainer-led governance during the implementer-draft phase.

## Roles

### Project lead

Bilal Medjani is the initial project lead. The project lead is accountable for
releases, security embargoes, governance, and changes to the protocol contract.
The project lead can appoint maintainers through a public update to this file.

### Maintainers

Maintainers review changes, triage issues, operate releases, and protect the
documented security and compatibility boundaries. A maintainer role requires
the person's consent and verified repository access.

### Contributors

Any person can propose a change. Contribution does not grant maintainer status
or authority to publish a release.

## Decisions

Routine changes use public issues and pull requests. Maintainers seek agreement
based on the specification, test evidence, and stated trade-offs. The project
lead resolves a deadlock during the current governance phase.

The project lead must approve these changes:

- a release or support-status change;
- a record, schema, canonicalization, or digest change;
- an authority, claim, dispatch, or reconciliation change;
- a weaker security requirement;
- a dependency with material supply-chain impact;
- a license, governance, or contribution-policy change;
- a public security advisory.

Security work can remain private until a fix or mitigation is available.

## Protocol changes

A normative change must include a compatibility decision. The change must also
update the required schemas, vectors, implementations, tests, and formal-model
assessment. See [CONTRIBUTING.md](./CONTRIBUTING.md).

Breaking changes require a new protocol profile or major version. A released
schema identifier is immutable.

## Releases

An official release must:

1. Follow [the release checklist](./.github/RELEASE_CHECKLIST.md).
2. Use a version tag published from this repository.
3. State the support level and compatibility impact.
4. State the tests and formal checks that were run.
5. State known limits and whether external review occurred.

No repository-maintained test, model, or automated review is external
assurance.

## Amendments

Propose a governance change by pull request. The pull request must explain the
reason, effect, and transition. The project lead approves the final text during
the maintainer-led phase.

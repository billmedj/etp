# Versioning policy

ETP versions protocol profiles, schemas, reference implementations, and effect
profiles separately when their compatibility boundaries differ.

## Protocol status

Version 0.1 is an implementer draft. No compatibility guarantee applies across
unreleased commits. A tagged pre-1.0 release can contain a breaking change when
the release notes identify the change and migration.

## Protocol profile

The Core profile uses a `major.minor` identifier.

- Increase `major` for an incompatible record, encoding, digest, lifecycle, or
  conformance change.
- Increase `minor` for an additive change that an older conforming verifier can
  reject without unsafe acceptance.

A released profile identifier and schema identifier are immutable. A correction
that changes accepted bytes or behavior requires a new identifier.

## Software versions

Reference software uses Semantic Versioning when it is tagged:

- `MAJOR`: incompatible public API or protocol-support change;
- `MINOR`: backward-compatible feature;
- `PATCH`: backward-compatible fix.

Pre-release identifiers show that an artifact is not a stable release. Software
versioning does not change the version of the protocol profile that the software
implements.

## Effect profiles

Each effect profile has its own immutable identifier. A change to target
identity, typed arguments, pre-state, dispatch, observation, or reconciliation
semantics requires a new profile identifier.

## Deprecation

A release note must identify a deprecated profile or API. It must state the
replacement and the earliest removal version. A security defect can require
immediate rejection when continued support would permit unsafe acceptance.

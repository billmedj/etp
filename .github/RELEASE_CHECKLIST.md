# Release checklist

ETP has no public release until the project lead completes this checklist and
publishes a version tag from the official repository.

## Scope and version

- [ ] Select the software version and supported protocol profiles.
- [ ] Apply [VERSIONING.md](../VERSIONING.md).
- [ ] Confirm that every released schema and profile identifier is immutable.
- [ ] Record all breaking changes and migrations in `CHANGELOG.md`.
- [ ] Update `CITATION.cff` with the release version and release date.

## Source and legal review

- [ ] Confirm that the release commit contains no credentials, private data,
      personal paths, generated build output, or unpublished private material.
- [ ] Review `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md`.
- [ ] Regenerate and verify `evidence-summary.json` from the reviewed sources.
- [ ] Regenerate `SOURCE_MANIFEST.sha256`, then verify it from a clean checkout.
- [ ] Generate a dependency license inventory and software bill of materials
      for each binary artifact.
- [ ] Record the source commit and artifact SHA-256 digests.

## Protocol consistency

- [ ] Validate every JSON Schema.
- [ ] Validate every positive and negative vector.
- [ ] Run the Rust verifier and workspace tests.
- [ ] Run the TypeScript verifier tests.
- [ ] Run all 77 Core conformance cases.
- [ ] Run all reference-profile tests.
- [ ] Confirm that the implementations agree on shared commitments and errors.

## Formal checks

- [ ] Build the Lean project and record the toolchain version.
- [ ] Confirm the expected 23 theorem declarations and absence of admitted
      proof placeholders in the release source.
- [ ] Run TLC for `formal/tla/EffectTransaction.cfg` with the pinned tool.
- [ ] Record the TLC version, model digest, configuration digest, state count,
      distinct-state count, search depth, and result.
- [ ] State that bounded model checking is not an implementation-refinement or
      unbounded proof.

## Security and claims

- [ ] Review `THREAT_MODEL.md` and `IMPLEMENTATION_STATUS.md`.
- [ ] Confirm that release notes do not claim production fitness, standard
      status, interoperability, prompt-injection immunity, or external review
      without the required evidence.
- [ ] Resolve or document every security finding that affects the release.
- [ ] State whether an external security review occurred.

## Publication

- [ ] Create release artifacts only from the reviewed source commit.
- [ ] Publish a verifiable version tag.
- [ ] Publish release notes with support status, evidence, known limits, and
      compatibility impact.
- [ ] Verify the public source archive and each published artifact after upload.

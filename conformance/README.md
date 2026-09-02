# Effect Transaction conformance suite

This directory contains the vendor-neutral suite for the Effect Transaction
Core 0.1 profile. The suite expresses fail-closed requirements as deterministic
cases. It writes a machine-readable JSON report.

The suite covers four areas:

- canonical transport and commitment encoding;
- structural transaction-chain verification;
- currentness and single-use grant claims;
- receipts and append-only reconciliation.

The runner has no third-party dependencies. It imports the separate TypeScript
verifier for structural checks. It does not implement a second verifier.

An in-memory lifecycle target supplies the stateful operations that a stateless
bundle verifier cannot provide. These operations include registration,
currentness checks, claims, and receipts. This target is a conformance oracle.
It is not a production claim store.

The runner reads non-mutation cases from
`../vectors/conformance-traces.json`. It validates the operation vocabulary and
replays each trace. It does not select behavior from a case identifier.
`trace.schema.json` defines the trace format.

## Run the suite

Use Node.js 22.6 or later. Run this command from the repository root:

```console
node --experimental-strip-types conformance/runner.ts
```

Use this command to write the complete report:

```console
node --experimental-strip-types conformance/runner.ts --report effect-transaction-conformance-report.json
```

The process exits with one of these codes:

- `0`: every observed result contains all fields declared in `manifest.json`;
- `1`: behavior differs from the manifest;
- `2`: runner arguments, the manifest, or test infrastructure are invalid.

The report includes the manifest SHA-256 digest, implementation identity,
execution environment, category totals, and each expected and observed result.
It has no clock-dependent fields. Identical environments therefore produce
stable reports.

## Test data

`manifest.json` is the case index and expected-result contract.

`../vectors/conformance-mutations.json` defines JSON Pointer mutations against
`../vectors/positive-chain.json`. This design separates the attack data from
the runner. Another implementation can consume the same mutations.

`../vectors/conformance-traces.json` defines each non-mutation case as a
sequence of lifecycle, transport, or canonicalization operations. The runner
rejects:

- duplicate trace identifiers;
- unknown fields or operations;
- invalid parameter types;
- traces that are not in the manifest;
- manifest cases that have no mutation or trace.

### Competing claims

The trace corpus labels `claim.competing` as `sequential_lifecycle`. The trace
replays eight claims in sequence. The required result is one successful claim
and seven single-use rejections.

This case does not test thread safety, database linearizability, or concurrent
exclusion. The SQLite implementation has a separate concurrent test:
[`two_connections_cannot_claim_the_same_grant`](../crates/effect-transaction-sqlite/src/lib.rs).
It opens two independent connections. A `Barrier` releases two worker threads.
The test requires exactly one committed winner.

Run that test with this command:

```console
cargo test --locked -p effect-transaction-sqlite two_connections_cannot_claim_the_same_grant
```

The corpus covers:

- substitutions in each record binding;
- each predecessor link;
- competing claims, replay, and conflicting grants;
- audience, epoch, pre-state, resource, revocation, and time failures;
- ambiguous dispatch and conflicting receipts;
- reconciliation forks, sequence gaps, time rollback, terminal extension, and
  history limits;
- duplicate keys, invalid UTF-8, control characters, Unicode scalar ordering,
  numeric malleability, and parsing limits.

## Use with another implementation

Keep the case identifiers and expected codes. Replace the TypeScript verifier
and in-memory lifecycle target with the implementation under test. Do not map
rejected cases to acceptance.

A stricter implementation can reject a case earlier. A conformance report MUST
document each error-code difference. It MUST NOT accept a case that the
manifest marks for rejection.

A passing report shows compatibility with the tested Core 0.1 boundaries. It
does not prove role authentication, durable linearizability, target-specific
effect semantics, or production fitness.

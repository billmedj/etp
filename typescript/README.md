# ETP verifier for TypeScript

This package verifies the structure and commitments of an ETP Core 0.1 record
chain. It has no dependencies. Transport object order is not trusted.

The verifier checks:

- the schema and value constraints for each core record;
- canonical JSON encoding;
- domain-separated SHA-256 commitments;
- predecessor digests and repeated lifecycle bindings;
- nested validity intervals;
- the single-use `uses: 1` grant field;
- the rule that only `allow` can produce a grant;
- receipt timing and `unknown` outcomes; and
- reconciliation linkage, sequence, and terminal states.

These reconciliation outcomes are terminal:

- `effect_confirmed`;
- `no_effect_confirmed`; and
- `compensated`.

`still_unknown` and `partial_effect` can have a later reconciliation record.
No record can follow a terminal outcome.

Receipt structure also depends on the outcome:

- `not_dispatched` requires `dispatched_at_ms: null`.
- `succeeded` and `failed` require a dispatch timestamp.
- `unknown` permits either timestamp form.

The verifier does not establish that observation evidence is true. Only a
conforming profile and executor can establish `not_dispatched`. Recovery MUST
preserve `unknown` when the available evidence is not sufficient.

This package does not verify signatures, authority roles, credential custody,
policy correctness, target state, complete mediation, or semantic evidence.
The deployment and effect profile must provide those controls.

## Requirements

Use Node.js 22.6 or later. Node.js runs the TypeScript source directly. The
package has no runtime or development dependencies.

```sh
npm test
npm run conformance
npm run verify -- ../vectors/positive-chain.json
npm run verify -- ../vectors/positive-not-dispatched.json
```

The verifier returns a nonzero exit code for malformed JSON, a schema error, a
commitment mismatch, or an invalid lifecycle transition.

`verify` accepts either a lifecycle bundle or the published test-vector
envelope. A vector envelope requires `profile`, `transaction`, and `expected`.
The verifier rejects unknown fields and an incorrect profile. The description
and expected result are test metadata. They are not part of a record
commitment.

The conformance command runs the portable Core 0.1 corpus. It writes a
machine-readable report. The corpus tests structural verification and the
stateful claim, currentness, and receipt oracle. A passing result shows
compatibility with the corpus. It is not a production certification.

## Resource limits

The parser rejects input above any of these limits:

| Limit | Value |
|---|---:|
| UTF-8 input size | 1 MiB |
| Nested containers | 64 |
| JSON values | 100,000 |
| Reconciliation records | 10,000 |

These limits apply before record validation.

## Identifier scope

Identifier uniqueness is scoped by record type and deployment trust domain.
This package rejects a repeated `reconciliation_id` in one chain. Issuers and
durable stores must enforce deployment-wide uniqueness for record and attempt
identifiers.

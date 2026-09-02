# Implementation status

**Status:** Implementer Draft 0.1

This document separates protocol design, reference code, test evidence, and
deployment claims. Evidence in one row does not establish a claim in another
row.

| Area | Implemented artifact | Repository evidence | Current limit |
| --- | --- | --- | --- |
| Core protocol | Six strict, content-addressed records and lifecycle rules | Specification, JSON Schemas, and positive and negative vectors | Draft protocol; no standards-body adoption |
| Canonicalization and structural verification | Rust and TypeScript verifiers | Shared commitments and cross-language rejection cases | Both implementations are maintained in this repository |
| Portable conformance | 77 machine-readable Core cases | Binding, issuance, claim, currentness, receipt, reconciliation, transport, and canonicalization tests | The stateful test target is an oracle, not a durable store |
| Record authentication | COSE Sign1 and Ed25519 authority profile with a Rust verifier | Positive, adversarial, byte-exact, and seeded mutation tests | A deployment must supply trust roots, key custody, revocation data, and trusted time |
| Durable lifecycle | Single-node SQLite WAL store | Concurrency, reopen, rollback, dispatch-marker, receipt, and reconciliation tests | No replicated consensus or atomic transaction with a remote target |
| Executor composition | Rust type-state executor | Core-chain validation, byte-exact document binding, claim, dispatch, recovery, receipt, and reconciliation tests | A deployment must validate effect-profile documents before this API and supply trusted target adapters with complete mediation |
| Conditional HTTP profile | Schemas and vectors for a strong validator and exact HTTPS target | Positive and adversarial vectors | Caller-side reference validator; no Rust HTTP adapter claim |
| Kubernetes JSON Patch profile | Schemas and vectors for object UID, `resourceVersion`, exact patch, and write set | Positive and adversarial vectors | Caller-side reference validator; no production cluster adapter claim |
| Formal model | 23 Lean theorem declarations for selected lifecycle invariants and one bounded TLA+ model | Lean build and TLC run for `EffectTransaction` | No model-to-code refinement proof, unbounded proof, or liveness proof |
| CLI | `etp verify` and `etp hash` | Shared-vector verification and profile-substitution rejection | Inspection only; the CLI does not authorize or execute an effect |
| Performance measurement | TypeScript verifier microbenchmark | Machine-readable local output | No host-independent or end-to-end latency claim |
| External assurance | None | No external audit report | Required before an external assurance claim |

## Formal-evidence boundary

The Lean source contains 23 theorem declarations for the protocol state model.
The repository also contains one TLA+ model and one TLC configuration. TLC
performs bounded state exploration for that configuration.

The Lean model omits wire encoding, cryptographic checks, and durable-storage
refinement. Its receipt abstraction does not include the post-claim
`not_dispatched` variant. Its reconciliation abstraction contains one terminal
observation and does not model `partial_effect`, `still_unknown`, or
`compensated`.

These results apply to the stated abstractions and bounds. They do not prove
that the Rust, TypeScript, SQLite, or effect-adapter code refines the models.
They do not establish unbounded safety or liveness.

## Supported claims

The repository implements a candidate transaction boundary for agent-proposed
effects. The records and reference code bind one proposal to an authorization
decision, current-state checks, a durable single-use claim, outcome evidence,
and append-only reconciliation.

## Unsupported claims

The repository does not establish:

- recovery of private or unstated human intent;
- prompt-injection immunity;
- truth of semantic, policy, human, or target evidence;
- production fitness or regulatory compliance;
- implementation refinement from the formal models;
- interoperability with an externally maintained implementation;
- ecosystem adoption or standard status.

These claims require additional specifications, integrations, tests, review,
and operational evidence.

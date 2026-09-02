# ETP core

`effect-transaction-core` defines the records and lifecycle rules of the Effect
Transaction Protocol (ETP). The crate does not depend on a model provider,
policy engine, or effect target.

An ETP transaction is an immutable, content-addressed chain:

```text
TaskCommitment
  -> EffectProposal
  -> AuthorizationDecision
  -> ExecutionGrant
  -> EffectReceipt
  -> ReconciliationRecord (if the outcome is unknown)
```

The crate provides:

- bounded parsing for untrusted JSON input;
- deterministic canonical JSON and domain-separated SHA-256 commitments;
- validation for each record and each link in the chain;
- validation for partial and complete transaction lifecycles; and
- an in-memory reference store for issuance, single-use claims, receipts, and
  reconciliation.

The in-memory store demonstrates protocol semantics. It is for tests and local
prototypes. It checks a currentness snapshot supplied by the caller, but it does
not authenticate that snapshot. It also cannot make external state changes
atomic with a claim.

A production store must provide durable transactions, replay tombstones, and a
trusted currentness source. The target adapter must use conditional mutation,
an idempotency key, or an equivalent fence.

This crate does not interpret natural language, make policy decisions, execute
effects, manage signing keys, or attest to target state.

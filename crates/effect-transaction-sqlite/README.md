# ETP SQLite store

`effect-transaction-sqlite` provides durable, single-node storage for ETP. It
uses short `BEGIN IMMEDIATE` transactions for chain registration, currentness
updates, grant claims, dispatch markers, receipts, and reconciliation.

## Storage properties

- Each connection enables WAL mode, `synchronous=FULL`, foreign keys, a bounded
  busy timeout, and `trusted_schema=OFF`.
- The database has an explicit schema version. The store rejects an unknown
  version and a non-empty database that has no version.
- Chain registration is idempotent. A proposal and an authorization decision
  can each issue at most one grant.
- Currentness records are monotonic. A claim checks the record version, epochs,
  target pre-state, resource claim, revocation state, and freshness in the same
  transaction that consumes the grant.
- Each grant has one winning attempt. Attempt identifiers are globally unique.
- The store writes `dispatch_started` before it accepts a dispatched receipt.
- Each attempt has one ledger receipt. Reconciliation records are append-only,
  parent-linked, bounded, and fork-free.

## Call sequence

1. Call `register_chain`.
2. Call `put_currentness`.
3. Call `claim`.
4. Call `mark_dispatch_started` immediately before the external call.
5. Call `record_receipt`.
6. Call `append_reconciliation` only if the receipt outcome is `unknown`.

## Trust boundary

This crate is not a distributed consensus system. `put_currentness` only fences
facts stored in this database. The target adapter must apply the same version or
fencing token to the external mutation. SQLite cannot make a remote API part of
its transaction.

The dispatch marker reduces crash ambiguity but does not remove it. A process
can stop after it writes the marker and before it records the remote result. In
this case, the receipt outcome must be `unknown` unless target-side evidence
proves the result. The marker alone does not prove that the effect occurred.

The store validates ETP structure and bindings. It does not authenticate
principals, sign records, protect the database from a privileged host, or
provide replication, backup, key management, or remote attestation.

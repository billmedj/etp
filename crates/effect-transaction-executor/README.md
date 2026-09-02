# ETP executor

`effect-transaction-executor` provides the reference authorization and
dispatch boundary for one ETP effect. It combines record validation, COSE and
Ed25519 authority verification, and the SQLite lifecycle store. It does not
implement a shell, network, cloud, or model adapter.

## Execution sequence

1. A profile-aware caller validates the four proposal documents against the
   selected profile's schemas and semantic rules. It then supplies their
   canonical bytes.
2. `PreparedEffect::new` validates the task-to-grant chain, the document byte
   limits, and the four exact SHA-256 bindings. It treats document bytes as
   opaque. It does not run the HTTP or Kubernetes profile validator.
3. `EffectTransactionExecutor::authorize_and_claim` verifies a current
   authority assertion for the grant. It then registers the chain, advances
   currentness, and atomically claims the grant.
4. The returned `ClaimedEffect` exposes audit identifiers. It does not expose
   target data.
5. `begin_dispatch` verifies the authority again with a fresh host snapshot. It
   checks target currentness and writes the dispatch marker before it returns a
   `DispatchCapability`.
6. `DispatchCapability::dispatch_with` consumes the capability and passes one
   `ExactEffect` value to a caller-supplied adapter.
7. The resulting `ReceiptHandle` records one `succeeded`, `failed`, or `unknown`
   outcome. Before dispatch starts, the caller can close the claim as
   `not_dispatched`.
8. Recovery closes a crash before the dispatch marker as `not_dispatched`. It
   closes a crash after the marker as `unknown`. Reconciliation can then record
   target-side evidence.

## Enforced controls

- The authority signature covers the execution-grant commitment. The profile
  uses COSE Sign1 and Ed25519.
- Verification checks the issuer, key, role, audience, record binding, epochs,
  validity intervals, revocation state, and snapshot freshness.
- The currentness check binds the policy epoch, configuration epoch, target
  pre-state, resource claim, and grant audience.
- The executor verifies the digest of each exact profile-document byte string.
- SQLite provides the atomic claim and durable dispatch marker under its stated
  durability assumptions.
- The API does not release target data before the dispatch marker is durable.

## Trust boundary

The host must provide authenticated clock and currentness snapshots. The host
must also configure trusted keys. Before it calls `PreparedEffect::new`, the
host must run a profile-aware schema and semantic validator. The target adapter
must use conditional mutation or an idempotency key that honors the ETP fence.

This crate cannot make a SQLite transaction atomic with a remote service. A
malicious adapter can copy an effect or call a target more than once. The
`FnOnce` boundary prevents accidental reuse by the caller; it does not contain
hostile adapter code.

A timeout or lost response does not prove failure. After dispatch starts, the
executor records `unknown` unless the target profile provides conclusive
evidence of success or failure.

## Verify the crate

```powershell
cargo test --locked -p effect-transaction-executor
cargo clippy --locked -p effect-transaction-executor --all-targets -- -D warnings
```

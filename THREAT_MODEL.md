# Effect Transaction Protocol threat model

**Status:** Implementer Draft
**Applies to:** `effect-transaction/core/0.1`

This document defines the ETP adversaries, trusted components, security goals,
and residual risks. It is normative for security claims about the reference
implementation. The protocol specification defines the wire format and
conformance requirements.

## Protected transition

ETP protects this external-effect transition:

```text
authenticated task authority
        -> exact untrusted proposal
        -> independent authorization decision
        -> audience-bound single-use grant
        -> durable claim and dispatch journal
        -> profile-defined observation
        -> reconciliation after an unknown outcome
```

ETP treats model output, plans, retrieved content, tool descriptions, tool
arguments, and remote responses as untrusted data. These inputs cannot create
or expand authority.

## Protected assets

ETP protects:

- the authority committed by a task owner;
- the target, operation, arguments, expected effect, pre-state, and resource
  claim authorized for one attempt;
- the current policy, configuration, keys, revocations, and target state;
- the single-use state of an execution grant;
- the order of claim, dispatch, completion, and reconciliation;
- the integrity and origin of records and referenced documents;
- the distinction between proven non-dispatch and an unknown outcome.

## Adversaries and faults

An implementation that claims the applicable conformance class must preserve
safe behavior under these conditions:

| Adversary or fault | Required behavior |
| --- | --- |
| Compromised or prompt-injected requester | The requester can propose arbitrary effects. It cannot issue a decision or grant |
| Argument, target, state, resource, or profile substitution | Full-chain verification rejects the changed binding |
| Records combined across tasks or profiles | Domain separation and predecessor hashes reject the chain |
| Grant theft or replay | Audience checks, authenticated presentation, and durable single-use claim reject reuse |
| Concurrent claims | At most one claimant crosses the claim linearization point |
| Stale policy, configuration, key, revocation, or target state | A currentness check serialized with claim rejects the attempt |
| Clock rollback | The executor fails closed until trusted time restores monotonicity |
| Crash before dispatch | The executor records `not_dispatched` only when durable ordering proves that external I/O could not start |
| Crash, timeout, or partition near dispatch | The executor records `unknown`, keeps the grant consumed, and prevents blind retry |
| Duplicate receipt or reconciliation fork | Durable uniqueness and parent binding reject conflicting continuations |
| History rollback to an older consistent head | Local verification cannot detect the rollback. Detection needs protected monotonic state, replicated consensus, or an authenticated external anchor |
| Malformed or resource-exhausting input | Bounded parsing rejects the input before unbounded work |
| Untrusted observation | The system retains it as scoped evidence. It cannot expand authority or prove a broader objective |

## Trust assumptions

ETP reduces the authority available to an agent. It does not remove trusted
components. A deployment must identify and protect these components:

1. **Task authority.** It authenticates the principal. It commits the effective
   objective, constraints, scope, epochs, and validity interval.
2. **Evaluator trust policy.** It selects authorized evaluators and evidence
   sources. A compromised authorized evaluator can allow a harmful proposal.
3. **Grant issuer.** It protects its signing identity. It enforces one grant per
   proposal and decision.
4. **Transactional store.** It preserves issuance tombstones, currentness,
   claims, attempt journals, receipts, and reconciliation order after restart.
5. **Executor identity and isolation.** The audience identifies an
   authenticated executor trust domain. It is not a caller-supplied label.
6. **Trusted time.** Expiry and rollback checks need a documented time source
   and rollback strategy.
7. **Target concurrency control.** A mutating profile needs a target-side
   conditional operation or a fenced reservation held through dispatch.
8. **Profile registry.** Profile identifiers resolve to immutable schemas and
   semantics. The registry prevents downgrade and mutable aliasing.
9. **Key distribution and revocation.** Authentication depends on trust roots,
   key lifecycle, and current revocation data.

A deployment can combine roles in one process. This does not remove the trust
boundaries. The deployment profile must state the larger failure domain.

## Security goals

### Exact-effect integrity

The executor dispatches only the typed effect bound by the accepted task,
proposal, decision, and grant. A model explanation cannot replace a committed
parameter.

### Authority non-amplification

Evidence, approvals, model output, reconciliation, and prior success cannot
expand task authority. A repeated or compensating effect requires a new
transaction.

### At-most-one authorized attempt

One proposal and decision produce at most one grant. One grant has at most one
successful claim. The ledger accepts at most one immutable receipt for that
attempt.

This goal applies to authorization and attempts. It does not guarantee
exactly-once delivery or the truth of external observations.

### Uncertainty preservation

The executor does not infer success, failure, or non-dispatch from missing
evidence. An ambiguous dispatch has outcome `unknown`. It creates a durable
reconciliation obligation.

### Verifiable provenance

An independent verifier can recompute each structural binding. Authentication
envelopes bind the role, signer, profile, audience, record kind, and record
digest. A valid hash does not authenticate the record origin.

## Non-goals and residual risks

ETP does not independently:

- determine whether the system interpreted natural-language intent correctly;
- make a compromised authority, evaluator, issuer, executor, or trust root
  trustworthy;
- prevent an authorized effect with incorrectly modeled consequences;
- encrypt records or referenced documents;
- prove code identity, hardware state, or workload isolation;
- give exactly-once semantics to a non-idempotent remote API;
- guarantee availability during a partition or trusted-source failure;
- detect full database rollback without protected monotonic state, replicated
  consensus, or an external transparency anchor;
- prove that an observation satisfies the user's broader objective;
- replace workload identity, policy, target concurrency control, key
  management, audit retention, or incident response.

## Prompt-injection claim boundary

ETP prevents untrusted content from directly creating authority or changing an
authorized effect after the decision. It also supports independent evaluation
before grant issuance.

ETP cannot provide this protection if the same compromised model acts as the
task authority or trusted evaluator. It also cannot prevent an authorized
evaluator from allowing an attacker's proposal.

A prompt-injection resistance claim therefore needs an independent authority
path. It also needs task and effect profiles that preserve control and data
provenance. A deployment must test these properties with adversarial inputs.

## Failure matrix

| Failure point | Safe stored state | Permitted next action |
| --- | --- | --- |
| Before grant issuance | No grant | Re-evaluate or abandon the proposal |
| After issuance and before claim | Unused grant | Claim once while all bindings are current, or let the grant expire or be revoked |
| After claim and before the durable dispatch marker | Claimed attempt | Record `not_dispatched` only if profile ordering proves that external I/O could not start |
| After the durable dispatch marker and before terminal evidence | Dispatch started | Record `unknown` and reconcile |
| After the terminal receipt | Consumed grant and immutable receipt | Do not dispatch again. Create a new transaction for another effect |
| After nonterminal reconciliation | Append-only reconciliation head | Append one child observation |
| After terminal reconciliation | Terminal head | Do not append a child or restore the grant |

## Deployment claim checklist

A production claim must identify evidence for each item:

- authenticated roles and algorithm policy;
- key rotation, revocation, and compromise recovery;
- trusted time and rollback handling;
- durable issuance and claim linearization;
- currentness source and consistency or fencing boundary;
- target-side conditional mutation or lease fencing;
- recovery tests at each persistence boundary;
- receipt and reconciliation uniqueness after restart;
- backup, restore, and database-rollback detection;
- parser and transport limits;
- effect-profile observation semantics;
- adversarial tests and measured false-allow and false-review rates;
- data retention, privacy, and operator escalation.

If a required fact is unavailable, the executor fails closed. It does not
downgrade to structural verification.

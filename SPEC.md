# Effect Transaction Protocol 0.1

**Status:** Implementer Draft
**Profile:** `effect-transaction/core/0.1`

## 1. Scope

Effect Transaction Protocol (ETP) defines an append-only record chain for
external effects proposed by untrusted agents. The chain covers authorization,
claim, execution, observation, and reconciliation.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are to be interpreted as described in BCP 14, RFC 2119, and
RFC 8174 when, and only when, they appear in capitals.

ETP separates proposals from authority. Model output, retrieved content, tool
arguments, and agent plans are untrusted inputs. These inputs can propose an
effect or supply evidence. They cannot create, expand, consume, or restore
authority.

## 2. Design objective

ETP protects this transition:

```text
committed task -> exact proposal -> independent decision -> single-use grant
               -> claimed dispatch -> evidence-based outcome -> reconciliation?
```

The protocol defines these properties:

- exact binding between an authorized proposal and the dispatched effect;
- current-state and configuration checks immediately before claim;
- durable, atomic, single-use grant consumption;
- separate outcomes for failure and uncertainty;
- append-only evidence;
- no blind retry;
- independent verification of the complete record chain.

## 3. Roles and trust boundaries

A deployment MAY combine roles in one process. It MUST preserve the checks and
authority boundaries defined for each role.

### 3.1 Requester

The requester creates an `EffectProposal`. A requester can be a model, agent
harness, workflow, extension, or human-operated client. The requester is not
trusted to authorize an effect.

### 3.2 Task authority

The task authority creates or authenticates a `TaskCommitment`. It establishes
the principal, objective, constraints, authority scope, policy epoch,
configuration epoch, and validity interval. It performs this work independently
of model output.

The objective and constraints can guide evaluation. Their text MUST NOT be
treated as machine authority.

### 3.3 Evaluator

The evaluator checks one immutable proposal. It checks the proposal against the
committed task, admitted evidence, current policy, current configuration,
target pre-state, and resource claims. It creates an
`AuthorizationDecision` with outcome `allow`, `deny`, or `review`.

An evaluator MAY use deterministic rules, formal checks, semantic comparison,
human approval, or a combination of these methods. Favorable evidence MUST NOT
expand the authority in the task commitment.

### 3.4 Grant issuer

The grant issuer creates an `ExecutionGrant` only from a valid `allow`
decision. It protects its signing or transport identity. It creates unique
grant identifiers and nonces. It retains the complete predecessor chain.

### 3.5 Claim store

The claim store provides a linearizable `unused -> consumed` transition for
one `grant_id`. A production claim store MUST be durable. It MUST preserve a
replay tombstone for the full recovery and reconciliation period.

### 3.6 Executor

The executor holds the operating-system or service authority for the effect. It
validates the complete chain. It checks current state. It atomically claims the
grant. It constructs the effect only from committed typed arguments. It
dispatches the effect and records an `EffectReceipt`.

### 3.7 Observer and reconciler

The observer obtains target-specific evidence about the effect. The reconciler
investigates an `unknown` receipt and appends a `ReconciliationRecord`.

A target response is evidence at a declared observation boundary. It does not
necessarily prove that the broader task objective was achieved.

## 4. Data model

Each protocol record is a strict JSON object. Its `version` value is `1`.
Unknown properties are not permitted.

Transport JSON follows RFC 8259 with the additional restrictions in Section 5.

The schemas in `schemas/` use JSON Schema Draft 2020-12. They are normative for
field shape. This specification is normative for ordering, cross-record,
hashing, and storage rules that JSON Schema cannot express.

JSON Schema `maxLength` counts Unicode scalar values. The Core limits below
count UTF-8 bytes. Schema validation is therefore only the structural check.
A Core verifier MUST enforce the byte limits after UTF-8 decoding. For example,
an identifier made of 256 U+00E9 characters satisfies a 256-character schema
limit but occupies 512 UTF-8 bytes and MUST be rejected.

Each identifier MUST meet these requirements:

- It is not empty.
- It has no leading or trailing whitespace.
- It contains no control character.
- Its UTF-8 encoding is not more than 256 bytes.
- It is unique within its record type and deployment trust domain.

UUIDs are RECOMMENDED but not required.

A digest uses `sha256:` followed by 64 lowercase hexadecimal characters. A
digest MUST NOT contain the all-zero SHA-256 value.

A time value is a Unix epoch time in milliseconds. It is a non-negative JSON
safe integer. An implementation MUST use a trusted monotonicity strategy for
security decisions. It MUST fail closed if clock rollback could make an expired
grant valid.

Core profile limits are:

| Value | Limit |
| --- | --- |
| identifier | 256 UTF-8 bytes |
| `principal`, `audience` | 512 UTF-8 bytes |
| `effect_profile`, `operation`, reason code | 256 UTF-8 bytes |
| `target` | 4,096 UTF-8 bytes |
| evidence hashes per decision | 256 |
| reason codes per decision | 64 |
| grant nonce | 22 to 128 unpadded base64url characters |

Text fields MUST have no leading or trailing whitespace. They MUST contain no
control characters.

Operation and reason-code tokens MUST start with a lowercase ASCII character.
They can contain only lowercase ASCII letters, digits, period, underscore,
colon, solidus, or hyphen.

The grant nonce uses the URL-safe alphabet in RFC 4648 Section 5 without
padding. It MUST contain at least 128 bits of cryptographic entropy. Profiles
MAY set lower limits. They MUST NOT increase a Core limit.

### 4.1 `TaskCommitment`

`TaskCommitment` is the portable root of the authority context. It contains:

- `commitment_id` and `principal`;
- `objective_digest`, `constraints_digest`, and `authority_scope_digest`;
- `policy_epoch` and `configuration_epoch`;
- `created_at_ms` and `expires_at_ms`.

The three digests refer to separate task documents. The task profile MUST
define the schema and canonicalization for these documents.

A change to the effective objective, constraints, or authority scope MUST
produce a new commitment. A change to security policy or security-relevant
configuration MUST produce a new commitment or increment the applicable epoch.
A deployment MUST NOT expand an existing commitment without one of these
changes.

`expires_at_ms` MUST be later than `created_at_ms`.

### 4.2 `EffectProposal`

`EffectProposal` describes one external effect before authorization. It
contains:

- `proposal_id` and `commitment_hash`;
- `effect_profile`, `operation`, and the exact `target` identity;
- `arguments_digest` and `expected_effect_digest`;
- `pre_state_digest` and `resource_claim_digest`;
- `created_at_ms` and `expires_at_ms`.

The effect profile MUST define:

- the typed documents committed by these digests;
- target identity rules;
- the state observation boundary;
- resource-claim semantics;
- dispatch behavior;
- the reconciliation procedure.

The proposal validity interval MUST be within the task validity interval. A
mutable target alias is not sufficient if it can redirect authority after
evaluation. Every security-relevant parameter MUST be in a committed document.

### 4.3 `AuthorizationDecision`

`AuthorizationDecision` is the independent result for one exact proposal. It
contains:

- `decision_id` and `proposal_hash`;
- sorted and duplicate-free `evidence_hashes`;
- `outcome`: `allow`, `deny`, or `review`;
- sorted, duplicate-free, and stable `reason_codes`;
- `decided_at_ms` and `expires_at_ms`.

At least one reason code is REQUIRED.

An `allow` decision requires at least one admitted evidence hash. A `deny`
or `review` decision MAY have an empty evidence list.

Each evidence document MUST identify its source, scope, configuration, and
observation time. The applicable effect or evaluator profile defines these
fields.

`review` means that the evaluator needs independent input before it can
authorize the proposal. `review` is not authority. Human approval or new
evidence MUST produce a new decision. A transport message that says
`approved` is not an execution grant.

The decision validity interval MUST be within the proposal validity interval.
Only an `allow` decision can support grant issuance.

### 4.4 `ExecutionGrant`

`ExecutionGrant` is short-lived, single-use execution authority. It contains:

- `grant_id`, `proposal_hash`, and `decision_hash`;
- `audience`, which identifies the executor trust domain;
- `not_before_ms` and `expires_at_ms`;
- `uses`, which MUST equal `1`;
- a unique and unpredictable `nonce`.

The predecessor hashes bind the grant to the task, arguments, expected effect,
target pre-state, resource claim, policy epoch, and configuration epoch. A
verifier MUST validate the complete predecessor chain. Validation of the grant
record alone is not sufficient.

The issuer MUST create a grant only from an `allow` decision. The grant MUST
name one audience. It MUST expire no later than the proposal or decision.

The Core profile permits a maximum grant lifetime of 300,000 milliseconds. A
short lifetime does not replace atomic, single-use consumption.

Grant issuance MUST be linearizable. One proposal can produce at most one
`grant_id`. One decision can produce at most one `grant_id`.

The issuer MUST store durable `proposal_hash -> grant_id` and
`decision_hash -> grant_id` tombstones. It MUST reject a second issuance even
if that issuance changes the decision, identifier, nonce, audience, or validity
interval.

An issuance retry returns the stored grant or fails closed. It does not create
new authority.

### 4.5 `EffectReceipt`

`EffectReceipt` is immutable evidence for one consumed grant and one attempt.
It contains:

- `receipt_id`, `proposal_hash`, and `grant_hash`;
- `attempt_id`;
- `claimed_at_ms`, nullable `dispatched_at_ms`, and `completed_at_ms`;
- `outcome`: `not_dispatched`, `succeeded`, `failed`, or `unknown`;
- `observation_digest`.

The timestamps MUST satisfy
`claimed_at_ms <= completed_at_ms`. If `dispatched_at_ms` is present, the
timestamps MUST also satisfy
`claimed_at_ms <= dispatched_at_ms <= completed_at_ms`.

The receipt MUST bind the same proposal as the grant. The observation document
MUST distinguish these facts:

- what the executor sent;
- what the target reported;
- what an independent observer found;
- what remains unknown.

The effect profile defines the observation boundary.

`dispatched_at_ms` records the durable transition to `DISPATCH_STARTED`.
The executor records it immediately before it permits external I/O. This value
does not prove that a call began or that the target accepted an effect. A crash
after this marker therefore has outcome `unknown` unless evidence accepted by
the effect profile resolves the outcome.

`not_dispatched` requires a null dispatch timestamp. It also requires durable
evidence that the executor did not cross the dispatch boundary.

`succeeded` requires a dispatch timestamp. It means that evidence shows
success at the declared observation boundary.

`failed` requires a dispatch timestamp. It means that evidence shows failure
at the declared observation boundary.

Neither `succeeded` nor `failed` states that the broader objective was
achieved.

`unknown` can have a present or null dispatch timestamp. Recovery can know
that dispatch started, or it can lack enough evidence to decide whether the
effect occurred.

A null dispatch timestamp does not mean `not sent`. That meaning applies only
when the outcome is `not_dispatched` and the profile's durable ordering rule
proves it.

### 4.6 `ReconciliationRecord`

`ReconciliationRecord` appends evidence after a receipt. It normally follows
an `unknown` receipt. It contains:

- `reconciliation_id`, `receipt_hash`, and increasing `sequence`;
- `parent_reconciliation_hash`;
- `observed_at_ms`;
- `outcome`: `effect_confirmed`, `no_effect_confirmed`,
  `partial_effect`, `still_unknown`, or `compensated`;
- `evidence_digest`.

Core reconciliation is valid only for a receipt with outcome `unknown`.

The first record MUST have sequence `1`. Its parent hash MUST be `null`.

Each later record MUST increment the sequence by one. It MUST name the previous
reconciliation hash. Its observation time MUST be no earlier than the receipt
completion time. It MUST also be no earlier than the previous reconciliation
time.

`effect_confirmed`, `no_effect_confirmed`, and `compensated` are terminal
outcomes. A reconciliation record MUST NOT follow a terminal outcome.

`partial_effect` and `still_unknown` are nonterminal outcomes. Another
observation can follow them.

Reconciliation records form an append-only chain. They MUST NOT change a
receipt. They MUST NOT restore a consumed grant. They MUST NOT authorize a
retry or compensation.

A repeated or compensating effect requires a new proposal, decision, and grant.

### 4.7 Lifecycle bundle and test-vector envelope

`transaction-bundle-0.1.schema.json` defines the transport shape for one lifecycle
prefix. It is not a seventh record. It has no digest or authority of its own.

The bundle contains:

- `commitment`;
- `proposal`;
- `decision`;
- optional `grant`;
- optional `receipt`;
- optional `reconciliations` array.

An absent optional record and an explicit JSON `null` have the same lifecycle
meaning. An absent `reconciliations` array has the same meaning as an empty
array. A non-empty reconciliation array requires a non-null receipt.

`test-vector-envelope-0.1.schema.json` defines a publication container for test
fixtures. It is informative. It contains:

- the exact Core profile identifier;
- an optional description;
- one bare bundle in `transaction`;
- the required result in `expected`.

Envelope metadata is not part of any record digest, chain binding, decision,
grant, or authority assertion. An implementation MUST remove the envelope
before protocol verification. It MUST reject unknown envelope fields. It MUST
reject a profile mismatch.

Each non-local JSON Schema reference in the Core bundle is an absolute URI
under `https://billmedj.github.io/etp/schemas/`. The URI equals the target
schema `$id`. A validator MAY resolve these URIs from the profile inventory. It
does not need network access when it has an authenticated local inventory.

The schema files use versioned names. A published schema URI is immutable.

## 5. Canonical JSON

Record commitments use a restricted canonical JSON format. The restriction
lets independent implementations produce the same bytes.

This format is an ETP protocol encoding. It is not the JSON Canonicalization
Scheme (JCS) in RFC 8785. ETP uses Unicode scalar-value ordering and accepts
integers only. JCS uses different key-order and number-serialization rules.
The two encodings are not interchangeable.

### 5.1 Accepted values

The canonicalizer MUST accept only:

- `null`;
- Boolean values;
- strings made of Unicode scalar values;
- integers in `[-9007199254740991, 9007199254740991]`;
- arrays of accepted values;
- objects with string keys and accepted values.

In this specification, a Unicode scalar value is a code point from U+0000 to
U+10FFFF, excluding surrogate code points U+D800 through U+DFFF. UTF-8 encoding
follows RFC 3629.

The canonicalizer MUST reject:

- floating-point values;
- exponent notation;
- negative zero;
- integers outside the safe range;
- duplicate object keys;
- lone UTF-16 surrogates;
- non-JSON host-language values.

The canonicalizer MUST NOT normalize Unicode. Different Unicode scalar
sequences remain different commitments.

A Core parser MUST reject transport input larger than 1,048,576 bytes. It MUST
reject nesting deeper than 64 values. It MUST reject input with more than
100,000 JSON values.

A transaction bundle MUST contain no more than 10,000 reconciliation records.
An API MAY use smaller limits. It MUST report a limit failure before
canonicalization or hashing.

Record schemas further restrict integers to non-negative values. They also
restrict strings to the declared formats.

### 5.2 Encoding

The canonicalizer MUST:

1. encode `null`, `true`, and `false` as the exact ASCII tokens;
2. encode integers as minimal base-10 ASCII;
3. omit leading zeros and plus signs from integers;
4. preserve array order;
5. omit insignificant whitespace;
6. sort object keys by Unicode scalar-value sequence;
7. escape quotation mark and reverse solidus as `\"` and `\\`;
8. encode U+0008, U+0009, U+000A, U+000C, and U+000D as `\b`, `\t`,
   `\n`, `\f`, and `\r`;
9. encode each other U+0000 through U+001F control character as lowercase
   `\u00xx`;
10. encode all other Unicode scalar values directly as UTF-8.

Keys and values use the same string encoding. An implementation MUST NOT depend
on source property order, whitespace, or escape spelling.

### 5.3 Record digest

For record `R` of kind `K`:

```text
record_digest(R) =
  "sha256:" || lowercase_hex(
    SHA-256(UTF8(domain(K)) || 0x00 || canonical_json(R))
  )
```

The domain strings are:

| Record | Domain |
| --- | --- |
| `TaskCommitment` | `effect-transaction/0.1/task-commitment` |
| `EffectProposal` | `effect-transaction/0.1/effect-proposal` |
| `AuthorizationDecision` | `effect-transaction/0.1/authorization-decision` |
| `ExecutionGrant` | `effect-transaction/0.1/execution-grant` |
| `EffectReceipt` | `effect-transaction/0.1/effect-receipt` |
| `ReconciliationRecord` | `effect-transaction/0.1/reconciliation-record` |

SHA-256 is the algorithm specified in FIPS 180-4.

The applicable task, evaluator, or effect profile MUST define canonicalization
and domain separation for each referenced external document. A digest commits
to bytes. It does not prove that the document is true or authorized.

The reference effect profiles define their document bytes as the UTF-8
encoding of the restricted canonical JSON in this section. They hash those
bytes directly with SHA-256. Their required `profile`, `document_type`, and
`version` fields, together with the role-specific digest field in the Core
record, provide domain separation. A caller MUST validate those fields and the
profile's semantic rules before it invokes the Rust executor. The executor's
`PreparedEffect` type checks byte limits and digest equality; it does not parse
effect-profile documents.

## 6. Chain validation

A verifier MUST obtain and validate the full chain required by the record under
review. It MUST:

1. validate each record against its exact schema;
2. reject unknown versions and properties;
3. recompute each record digest as specified in Section 5;
4. verify each predecessor hash and repeated proposal binding;
5. verify identifier uniqueness within the available chain;
6. verify nonzero digests;
7. verify sorted and unique arrays;
8. verify nested validity intervals;
9. require decision outcome `allow` before it accepts a grant;
10. verify `uses == 1`;
11. verify executor audience, trusted time, revocation, and grant validity;
12. resolve committed task and effect documents under their profiles;
13. check current policy and configuration epochs immediately before claim;
14. check exact target identity, target pre-state, and resource claims
    immediately before claim;
15. fail closed when a required record, document, observation, or consistency
    fact is unavailable.

A valid signature or authenticated transport does not replace these checks. A
valid hash chain does not prove that task data, evidence, policy, or observation
is correct.

Verification without authenticated role bindings is **structural
verification**. It does not prove that an authorized task authority, evaluator,
issuer, or executor created the records.

## 7. Atomic single-use claim

The claim store MUST provide one linearizable transition for each `grant_id`:

```text
UNUSED -> CONSUMED(grant_hash, attempt_id, claimed_at_ms)
```

The transition MUST occur only after complete chain and currentness validation.
It MUST reject an unknown, mismatched, premature, expired, revoked, or consumed
grant. It MUST permit exactly one successful claimant under concurrency.

The transition MUST durably preserve the consumed state and replay tombstone.
It MUST fail closed if the store cannot establish the transition. It MUST occur
before the executor crosses the dispatch boundary.

A successful claim MUST create or update a durable attempt journal before
dispatch. The journal entry contains the grant hash, proposal hash, attempt
identifier, and claim time.

The journal MUST record a durable transition from `CLAIMED` to
`DISPATCH_STARTED` before external I/O. It MUST then record a terminal receipt
or `UNKNOWN`.

Recovery can find `CLAIMED` without `DISPATCH_STARTED`. It MAY record
`not_dispatched` only if profile ordering proves that external I/O could not
start.

Otherwise, recovery MUST record `unknown` when no trustworthy terminal receipt
exists. It MUST NOT infer non-delivery from absence alone.

A consumed grant MUST NOT return to `UNUSED`.

If the target supports idempotency, the executor MUST use `grant_id` as the
idempotency key. Target idempotency does not replace the authoritative claim
transition.

Claim is the authority linearization point. A revocation serialized before
claim MUST block the claim. A revocation serialized after claim cannot remove
the attempt. The executor handles it through observation, reconciliation, or a
new compensating transaction.

Policy, configuration, revocation, reservation, and claim state MUST share one
declared consistency boundary. Alternatively, a fail-closed fencing protocol
MUST join them.

A pre-state check before claim does not prevent a race before dispatch. Each
mutating effect profile MUST also require one of these controls:

- an atomic target-side conditional operation bound to the committed pre-state;
- an exclusive reservation with a fencing token held through dispatch.

Examples of target-side conditions include an ETag, compare-and-swap token, or
`resourceVersion`. If the executor cannot establish either control, it MUST
NOT claim safe mutation semantics.

## 8. Unknown outcomes and retry

After claim, a process failure, transport loss, timeout, or ambiguous response
can make delivery uncertain. The executor MUST record `unknown` when it cannot
distinguish effect from non-effect.

The executor MUST NOT assume failure. It MUST NOT assume success. It MUST NOT
reuse the grant.

An `unknown` receipt creates a durable reconciliation obligation. The
effect-specific reconciler SHOULD query trusted target state, an idempotency
key, a target transaction identifier, or another observation that the effect
profile accepts.

If no authoritative observation is available, the reconciler MUST preserve
`still_unknown`. It MUST require operator handling.

A retry after `no_effect_confirmed` still requires a new proposal chain. This
rule causes a new evaluation of policy, state, resources, and authority.

## 9. Effect profiles

Each referenced task, evaluator, evidence, and effect document MUST contain an
immutable and versioned profile identifier in its committed bytes.

Within the deployment trust domain, the identifier MUST resolve to one stable
meaning. Use content addressing or an authenticated append-only registry. A
mutable alias is not sufficient.

An effect profile MUST define:

- supported operations;
- exact target identity;
- typed argument and expected-effect documents;
- pre-state observation and freshness;
- resource claims and ownership;
- dispatch boundary and durable journal order;
- conditional mutation or fencing;
- idempotency behavior;
- observation rules for `not_dispatched`, success, failure, and `unknown`;
- reconciliation queries and evidence;
- handling of secrets and sensitive results.

A profile MAY require shorter validity intervals, stronger identity,
additional evidence, reservations, signatures, or approvals.

A profile MUST NOT allow grant issuance from a non-`allow` decision. It MUST
NOT allow more than one use. It MUST NOT bypass complete mediation. It MUST NOT
change prior records. It MUST NOT allow blind retry after `unknown`.

## 10. Authentication and confidentiality

Core records contain commitments. They do not contain embedded signatures.

When records cross a trust boundary, the deployment MUST authenticate record
origin. It MUST protect record integrity. It can use authenticated transport or
a standard signature envelope such as COSE or DSSE.

The selected envelope MUST bind the exact ETP record digest and signer role. A
deployment that claims authenticated verification MUST publish its mapping from
roles to trust roots. It MUST reject a valid signature from a key that is not
authorized for the record role.

The implementer-draft COSE Sign1 and Ed25519 profile in
`profiles/authority-cose-sign1-ed25519-0.1.md` defines one interoperable
envelope. It does not define PKI, key custody, trust-root enrollment, revocation
delivery, or trusted time.

Records and referenced documents can contain sensitive identities, targets, or
operational metadata. Deployments SHOULD store private content separately. They
SHOULD disclose only necessary commitments. They SHOULD encrypt retained
evidence. They SHOULD apply access-control and retention rules to audit data.

## 11. Required invariants

A deployment that claims executor conformance MUST preserve these invariants
for each declared protected effect:

1. **No proposal-derived authority.** Untrusted model or content bytes cannot
   create or expand authority.
2. **Exact chain.** Each effect is bound to one valid commitment, proposal,
   `allow` decision, and grant.
3. **State-bound authority.** Target, arguments, pre-state, resource claims,
   policy epoch, and configuration epoch are current at claim time.
4. **Single issuance and use.** One proposal and one decision each issue at
   most one grant. At most one claimant consumes the grant.
5. **Complete mediation.** A protected effect cannot bypass the conforming
   executor.
6. **No blind retry.** An unknown effect is reconciled before a new attempt.
7. **Append-only, fork-free history.** One attempt has at most one canonical
   ledger receipt. One reconciliation head has at most one accepted child.
   Records are not rewritten to improve an apparent outcome.
8. **Evidence-limited claims.** A record states only facts established at its
   declared observation boundary.

## 12. Nonclaims

ETP conformance does not establish:

- recovery of private, unstated, or uniquely correct human intent;
- prompt-injection immunity for a model or user interface;
- truth of semantic, human, policy, or target evidence;
- correctness, usefulness, or safety of each authorized effect;
- achievement of the broader objective after successful dispatch;
- protection for effects outside the declared mediation boundary;
- universal rollback of irreversible or externally observed effects;
- correctness or availability of target systems, cryptographic libraries,
  keys, clocks, policy engines, or human approvers;
- refinement between a formal model and an implementation;
- legal, regulatory, or security-framework compliance;
- production readiness, performance, interoperability, or standard status.

These limits are part of the protocol.

## 13. Conformance

**Record conformance** requires exact schema validation, bounded parsing,
canonicalization, digest computation, and structural chain validation.

**Executor conformance** also requires:

- complete mediation;
- currentness checks;
- linearizable single issuance;
- durable atomic claim and attempt journal;
- fork-free authoritative append;
- evidence-based receipts;
- reconciliation for each declared protected effect.

An implementation MUST identify the protocol profile, effect profile, source
revision, canonicalization vectors, and storage consistency boundary used in
its tests.

One implementation passing its own tests is not evidence of cross-language
interoperability.

### 13.1 Validation failures

Before claim, the executor MUST reject an operation without dispatch when it
finds any of these conditions:

- invalid record;
- unsupported version;
- non-canonical value;
- digest or chain mismatch;
- decision other than `allow`;
- stale state;
- expired or premature grant;
- audience mismatch;
- revocation;
- missing evidence;
- unavailable claim store;
- unresolved required document.

Implementations SHOULD expose stable machine-readable error categories:

- `invalid_record`;
- `unsupported_version`;
- `noncanonical_value`;
- `digest_mismatch`;
- `chain_mismatch`;
- `not_authorized`;
- `not_current`;
- `grant_not_active`;
- `grant_consumed`;
- `claim_unavailable`;
- `reconciliation_required`.

An implementation MAY add a more specific subcode. It MUST NOT convert an
unknown validation or storage condition into authorization. Error responses
SHOULD NOT disclose committed private documents or secret target details.

## 14. Versioning

Core profile 0.1 accepts only record `version: 1`. An implementation MUST
reject an unknown version. It MUST NOT silently downgrade after a validation
failure.

A new compatible schema version or protocol profile is required when a change
affects a canonical record field, field meaning, encoding rule, domain string,
outcome, or invariant.

A change that weakens an invariant MUST NOT be described as backward
compatible.

## 15. References

- [BCP 14](https://www.rfc-editor.org/info/bcp14/):
  [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
  [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html).
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12): Core and
  Validation vocabularies.
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html): JSON syntax.
- [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629.html): UTF-8.
- [RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648.html#section-5):
  URL-safe Base64 alphabet.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html): JSON
  Canonicalization Scheme (JCS), which ETP does not use.
- [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-256.

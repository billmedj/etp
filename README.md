<img src="./assets/etp-mark.svg" alt="ETP mark" width="48" height="48">

# Effect Transaction Protocol

[![CI](https://github.com/billmedj/etp/actions/workflows/ci.yml/badge.svg)](https://github.com/billmedj/etp/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

**Protocol:** Core 0.1 implementer draft; **Reference software:**
0.1.0-alpha.1

Effect Transaction Protocol (ETP) defines an append-only record chain and
executor rules for externally visible actions proposed by untrusted agents.
An effect is one attempt to change or invoke an external target, such as an
HTTP request, Kubernetes patch, or file write.

An agent can propose an effect. An evaluator decides whether to allow the exact
proposal. A conforming executor validates the complete record chain and claims
a short-lived, single-use grant before dispatch. The executor then records the
observed outcome. If dispatch status is unclear, the outcome is `unknown` and
the grant remains consumed. Reconciliation adds evidence for the next operator
decision. It never restores the grant.

```text
TaskCommitment
      -> EffectProposal
      -> AuthorizationDecision
      -> ExecutionGrant
      -> EffectReceipt
      -> ReconciliationRecord?
```

Agent frameworks, policy languages, credential systems, transports, and
rollback engines remain outside the protocol. ETP defines a contract between
these components. Model output does not create execution authority.

## Why this boundary exists

Agent systems often authorize a broad tool or role, then let a model choose the
final target and arguments. This leaves a gap between policy approval and the
effect that reaches an external system.

ETP specifies a narrower boundary. It binds a grant to one typed proposal, one
observed pre-state, one executor audience, and one claim. It preserves an
`unknown` outcome when a crash or network failure makes the external result
unclear.

## Core properties

A conforming deployment preserves these rules for each protected effect:

1. A task authority commits the task independently of model output.
2. The proposal binds the target, arguments, expected effect, pre-state, and
   resource claim.
3. An evaluator returns `allow`, `deny`, or `review` for that proposal.
4. Only `allow` can produce a grant.
5. One proposal and one decision can each produce at most one grant.
6. The executor validates the complete chain and current state.
7. The executor atomically consumes the grant before dispatch.
8. The receipt records `not_dispatched`, `succeeded`, `failed`, or `unknown`
   from evidence at the declared observation boundary.
9. An `unknown` outcome prevents blind retry.
10. Reconciliation appends evidence. It does not rewrite history or restore a
    consumed grant.

## Repository layout

- [`SPEC.md`](./SPEC.md): protocol records, lifecycle, invariants, and
  conformance requirements.
- [`THREAT_MODEL.md`](./THREAT_MODEL.md): adversaries, trust assumptions,
  security goals, and residual risks.
- [`schemas/`](./schemas/): strict JSON Schema 2020-12 definitions.
- [`profiles/`](./profiles/): Core inventory, authority profile, and reference
  effect profiles.
- [`vectors/`](./vectors/): positive, negative, canonicalization, authority,
  and profile test vectors.
- [`conformance/`](./conformance/): 77 deterministic Core lifecycle cases.
- [`crates/`](./crates/): Rust core, authority, SQLite, executor, and CLI
  crates.
- [`typescript/`](./typescript/): a zero-dependency TypeScript structural
  verifier and CLI.
- [`formal/lean/`](./formal/lean/): 23 Lean theorem declarations for selected
  lifecycle safety invariants.
- [`formal/tla/`](./formal/tla/): one bounded TLA+ lifecycle model and its TLC
  configuration.
- [`IMPLEMENTATION_STATUS.md`](./IMPLEMENTATION_STATUS.md): implemented
  components, evidence, and limits.
- [`RELATED_WORK.md`](./RELATED_WORK.md): relationship to adjacent standards
  and systems.
- [`BENCHMARKS.md`](./BENCHMARKS.md): verifier benchmark method and limits.
- [`LANGUAGE.md`](./LANGUAGE.md): protocol terminology and public claim rules.
- [`BRAND.md`](./BRAND.md): visual identity and public writing guidance.

## Quick start

### TypeScript verifier

Requires Node.js 22.6 or later.

```console
cd typescript
npm test
npm run verify -- ../vectors/positive-chain.json
```

The TypeScript package has no runtime dependencies.

### Rust implementation

Use the Rust toolchain pinned by `rust-toolchain.toml`.

```console
cargo test --workspace --locked
cargo run --locked -p effect-transaction-cli -- verify vectors/positive-chain.json
```

### Conformance suite

Run from the repository root:

```console
node --experimental-strip-types conformance/runner.ts
```

Write a machine-readable report with:

```console
node --experimental-strip-types conformance/runner.ts --report effect-transaction-conformance-report.json
```

### Reference profiles

```console
cd profiles
npm ci --ignore-scripts
npm test
```

The profile suite validates the registered document schemas and 50 profile
vectors.

### Evidence checks

The repository pins Lean, TLA+ tools, Rust, and dependency lockfiles. The CI
evidence environment uses Node.js 24.10.0, Python 3.13, and Java 21. The local
JavaScript tools support Node.js 22.6 or later. Run these commands from the
repository root:

```console
python tools/check-language.py
python tools/check-site.py
python -m unittest discover -s tests -v
cd formal/lean
lake build
cd ../..
python tools/check-lean.py
python tools/fetch-tla2tools.py
python tools/run-tla.py
python tools/check-evidence.py
python tools/source-manifest.py --git git
```

`tools/run-tla.py` performs the declared finite search and rewrites the
deterministic result record. The checked-in counters do not replace that run.

## Integration model

```text
agent or workflow
        |
        v
ETP authority and claim boundary
        |
        v
conforming effect adapter
        |
        v
filesystem, HTTP service, Git host, cloud API, or Kubernetes API
```

An effect profile defines target identity, typed arguments, pre-state checks,
dispatch, observation, and reconciliation for one effect class. A profile can
add restrictions. It cannot expand task authority or weaken single-use and
unknown-outcome rules.

## Security and maturity

ETP 0.1 is an implementer draft. It is not an adopted standard, a production
certification, or an audited security product.

The repository provides Rust and TypeScript structural verifiers, a Rust
lifecycle store and executor, shared test vectors, 77 conformance cases, 23
Lean theorem declarations, and one bounded TLA+ model. These artifacts do not
prove implementation refinement, ecosystem interoperability, prompt-injection
immunity, or safe production deployment.
[`evidence-summary.json`](./evidence-summary.json) records the exact public
counts and source-set hashes used for these statements.

A deployment also needs complete mediation, durable atomic storage, trusted
configuration, protected keys, trusted time, validated effect profiles,
target-specific tests, and external review. See
[`THREAT_MODEL.md`](./THREAT_MODEL.md) and
[`IMPLEMENTATION_STATUS.md`](./IMPLEMENTATION_STATUS.md).

## Project policy

- License: [Apache License 2.0](./LICENSE)
- Identity and writing: [BRAND.md](./BRAND.md) and
  [LANGUAGE.md](./LANGUAGE.md)
- Security reports: [SECURITY.md](./SECURITY.md)
- Contributions: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Governance: [GOVERNANCE.md](./GOVERNANCE.md)
- Versioning: [VERSIONING.md](./VERSIONING.md)
- Support: [SUPPORT.md](./SUPPORT.md)

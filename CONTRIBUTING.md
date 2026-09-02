# Contributing to ETP

ETP accepts focused changes to the protocol, reference implementations, test
vectors, formal models, and documentation.

ETP 0.1 is an implementer draft. Do not disclose a vulnerability in a public
issue. Follow [SECURITY.md](./SECURITY.md).

## Before you change the protocol

Open a design issue before you change:

- a record field or schema identifier;
- canonical encoding or digest computation;
- authority, signing, audience, or currentness rules;
- grant issuance, claim, dispatch, receipt, or reconciliation behavior;
- an error code or conformance result;
- an effect-profile security boundary;
- a public security claim.

The proposal must state:

- the problem and affected invariant;
- the threat or interoperability failure;
- the trust assumptions;
- the proposed wire or state change;
- failure and recovery behavior;
- compatibility and migration impact;
- tests, vectors, and formal-model updates.

## Change requirements

A normative protocol change normally requires all applicable items:

1. Update `SPEC.md`.
2. Update the strict JSON Schemas.
3. Add positive and negative vectors.
4. Update the Rust and TypeScript verifiers.
5. Update the conformance manifest and cases.
6. Assess the Lean and TLA+ models.
7. Update the threat model and implementation status.
8. Record the user-visible change in `CHANGELOG.md`.

Do not change only one implementation to define protocol behavior.

## Development workflow

1. Create a branch from the current default branch.
2. Keep the change limited to one problem.
3. Add a failing test when practical.
4. Implement the smallest complete change.
5. Run the checks for every changed component.
6. Update the documentation and evidence boundary.
7. Open a pull request with the exact commands and results.

Do not commit credentials, private keys, customer data, personal paths,
generated packages, local databases, or unredacted logs.

## Evidence labels

Describe evidence by its actual type:

- unit test;
- property test;
- local integration test;
- conformance result for a named corpus;
- theorem for a named formal model;
- bounded model-checking result for a named configuration;
- external-system test;
- external review.

Do not describe repository-maintained tests or models as independent review.
Do not describe a formal model as proof of implementation refinement unless a
refinement argument exists.

## Pull requests

A pull request must include:

- the affected requirement or behavior;
- the security and compatibility impact;
- the commands that were run;
- the result of each command;
- generated files, schemas, vectors, and documentation that changed;
- any check that was not run and the reason.

## License

Unless a file states otherwise, contributions are submitted under the Apache
License 2.0 used by this repository. By submitting a contribution, you agree
that it is licensed on those terms. Preserve applicable copyright, license,
and attribution notices.

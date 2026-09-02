# Security policy

## Release status

ETP 0.1 is an implementer draft. The repository does not provide a supported
production release, a security certification, or a service-level agreement.

Security fixes before version 1.0 can change schemas, protocol behavior,
storage, and compatibility.

## Report a vulnerability

Use GitHub private vulnerability reporting for this repository:

1. Open the repository **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.

If private reporting is not available, use the contact method on the
[maintainer's GitHub profile](https://github.com/billmedj) to request a private
channel. Do not publish exploit details in an issue or discussion.

Include this information when it is safe to share:

- affected commit and platform;
- affected component and trust boundary;
- required access and preconditions;
- exact reproduction steps;
- observed and expected behavior;
- security impact;
- whether the test used credentials, external infrastructure, or private data;
- a minimal proof of concept.

Do not send live credentials, private keys, customer data, or unredacted logs.

## Reports in scope

Useful reports include:

- authorization without a valid current decision or grant;
- grant replay or more than one successful claim;
- target, argument, profile, pre-state, epoch, or audience substitution;
- a path that crosses a declared dispatch boundary without ETP mediation;
- a false `not_dispatched` outcome after external I/O can start;
- retry after an unresolved `unknown` outcome;
- conflicting receipts or reconciliation children;
- rollback that violates a documented protected-state assumption;
- parser ambiguity, acceptance of duplicate keys, or limit bypass;
- signature, role, audience, key, time, or revocation bypass;
- unintended disclosure of records, referenced documents, or keys.

## Claim boundary

The protocol does not make a compromised task authority, evaluator, issuer,
executor, trust root, or host trustworthy. The protocol also does not provide
an operating-system sandbox or exactly-once delivery to an arbitrary remote
target. See [THREAT_MODEL.md](./THREAT_MODEL.md).

A report remains relevant when the implementation behaves more permissively
than its specification, threat model, or declared boundary.

## Disclosure process

The maintainer will validate a report against the affected commit. The
maintainer will coordinate disclosure after a fix or documented mitigation is
available. Response times are best effort.

A security fix should add a regression test. It should also update the
specification, threat model, or implementation status when the affected claim
changes.

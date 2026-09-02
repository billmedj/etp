# Third-party notices

This file identifies source-level third-party material used by this repository.
Component source files, lockfiles, package metadata, and nested license files
remain authoritative.

## Contributor Covenant

[`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) adapts Contributor Covenant
version 2.1. Contributor Covenant was created by Coraline Ada Ehmke and is
stewarded by the Organization for Ethical Source. The adapted material is
licensed under the [Creative Commons Attribution 4.0 International
License](https://creativecommons.org/licenses/by/4.0/).

## JavaScript development dependencies

The reference-profile validation package pins these development dependencies:

| Package | Version | License |
| --- | --- | --- |
| Ajv | 8.20.0 | MIT |
| fast-deep-equal | 3.1.3 | MIT |
| fast-uri | 3.1.6 | BSD-3-Clause |
| json-schema-traverse | 1.0.0 | MIT |
| require-from-string | 2.0.2 | MIT |

These packages are used for schema validation in development and continuous
integration. They are not runtime dependencies of the TypeScript verifier.

## Rust dependencies

The Rust dependency graph is recorded in `Cargo.lock`. Each package remains
subject to its own license and attribution requirements. A binary distributor
must generate and review a license inventory for the exact release artifact.

## Development and verification tools

Lean, TLA+ tools, Rust, Node.js, Python, SQLite, and Git are not relicensed by
this repository. Each tool remains subject to its own license.

The TLA+ tools jar is not source material covered by the project license. If a
script downloads it, the script must verify the expected version and digest.

This source-level file is not a substitute for an artifact-specific software
bill of materials or legal review.

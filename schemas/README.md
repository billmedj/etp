# Core schemas

This directory contains the JSON Schema 2020-12 documents for ETP Core 0.1.

Each file name includes the protocol version. Its `$id` uses the same path
under `https://billmedj.github.io/etp/`. GitHub Pages serves these files from
the repository root. Implementations can register the schemas locally and use
the `$id` values to resolve cross-schema references without network access.

Core 0.1 is an implementer draft. A tagged schema version is immutable. A
breaking change requires a new file name, a new `$id`, and new conformance
vectors.

Run the schema checks from the repository root:

```console
cd profiles
npm ci --ignore-scripts
npm test
```

The schemas define transport structure. They do not replace the lifecycle,
authorization, target-profile, or durable-state checks in the specification.
JSON Schema `maxLength` counts Unicode scalar values. ETP text limits count
UTF-8 bytes. Rust and TypeScript verifiers enforce the normative byte limits
after decoding; schema validation alone is not sufficient.

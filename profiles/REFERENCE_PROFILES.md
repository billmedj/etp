# Reference effect profiles

This directory contains two implementer-draft effect profiles:

- `effect-transaction/http-conditional/0.1` defines one conditional HTTP
  mutation.
- `effect-transaction/kubernetes-json-patch/0.1` defines one Kubernetes JSON
  Patch mutation.

Each profile has seven JSON Schema 2020-12 documents. Every committed object
uses `additionalProperties: false`. A semantic validator checks rules that
JSON Schema cannot express. These rules include target canonicalization,
cross-document identity, dispatch order, and postconditions.

## Run the tests

Use Node.js 22.6 or later.

```sh
cd profiles
npm ci --ignore-scripts
npm test
```

The test command performs these checks:

1. It compiles the schema registries with the pinned Ajv version.
2. It validates each positive document.
3. It accepts each positive semantic vector.
4. It rejects each adversarial vector with the specified reason code.

The test suite does not need a cluster, a provider account, or credentials.
The vectors are in `vectors/profiles/`.

## Committed document bytes

The profile schemas and semantic validator operate on parsed JSON values. A
caller must complete both checks before it supplies a committed document to an
executor.

For each profile document `D`, the reference encoding is:

```text
B(D) = UTF8(canonical_json(D))
H(D) = "sha256:" || lowercase_hex(SHA-256(B(D)))
```

`canonical_json` is the restricted encoding in
[Section 5 of the Core specification](../SPEC.md#5-canonical-json). `B(D)`
contains no byte-order mark. The formatting of a vector file is not part of
the commitment; implementations canonicalize the selected document object.

The digest has no extra prefix. Domain separation is structural. Every schema
requires the exact `profile`, `document_type`, and `version` fields. The caller
must validate those fields and place `H(D)` in the record field for that
document role. A digest comparison without these checks is not profile
validation.

The Rust `PreparedEffect` API accepts the four proposal documents as opaque
exact bytes. It checks their size and SHA-256 bindings. It does not run these
HTTP or Kubernetes schema and semantic checks. A profile-aware adapter must
validate each document and pass `B(D)` to `PreparedEffect`.

The 0.1 vector corpus exercises `succeeded` and `unknown` receipts. It does
not claim exhaustive outcome mapping for `failed` or `not_dispatched`.

## HTTP target encoding

The target is the exact canonical HTTPS URI. The URI has these constraints:

- The host uses lowercase ASCII.
- The URI has no user information or fragment.
- Percent escapes use uppercase hexadecimal digits.
- Unreserved bytes are not percent-encoded.
- Query pairs are sorted by their encoded bytes.
- Redirects are not permitted.

## Kubernetes patch encoding

The arguments document contains both a parsed patch and
`patch_utf8_base64url`. The latter is the unpadded base64url encoding of the
exact UTF-8 request body. `patch_sha256` is the SHA-256 digest of those bytes.
The executor MUST send the decoded bytes without modification. The validator
requires the parsed patch to match the encoded bytes.

The target encoding is:

```text
k8s://<lowercase-cluster-trust-domain>/<canonical-api-path>?uid=<uid>
```

The query contains only `uid`. The draft rejects percent-encoded path and UID
variants. A later profile can change this rule only under a new version with
new test vectors.

## Conformance boundary

Passing the vectors shows conformance to these profile contracts. It does not
establish server correctness, control-plane integrity, DNS or TLS policy,
credential isolation, or durable ETP Core grant consumption. The executor and
deployment remain responsible for those properties.

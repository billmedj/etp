# Effect profile registry

An effect profile defines how ETP identifies, dispatches, and observes one
class of external effect. ETP Core does not define target-specific behavior.

This directory contains the implementer-draft profiles maintained with this
repository. It is not a global registry.

Each machine schema has an identifier under the repository-controlled
`https://billmedj.github.io/etp/profiles/` namespace. The identifier names the
schema version; it does not imply an IANA registration.

The terms MUST, MUST NOT, SHOULD, and MAY have the meanings defined in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

## Profile identifiers

| Identifier | Status | Effect |
|---|---|---|
| `effect-transaction/http-conditional/0.1` | Implementer draft | Conditional HTTP mutation with a strong validator |
| `effect-transaction/kubernetes-json-patch/0.1` | Implementer draft | Kubernetes JSON Patch bound to an object UID and `resourceVersion` |

[REFERENCE_PROFILES.md](REFERENCE_PROFILES.md) defines the validation method,
byte encoding, and test vectors. The authority profile is separate. It
authenticates ETP records but does not define an effect.

## Registration requirements

A stable profile MUST provide:

1. an immutable identifier and version;
2. a strict schema for each profile document;
3. a canonical encoding for each profile document;
4. one target identity algorithm;
5. one conditional mutation or fencing rule;
6. one durable dispatch boundary;
7. receipt and reconciliation rules;
8. positive and adversarial test vectors; and
9. two interoperable implementations that pass the same vectors.

An incompatible change MUST use a new identifier. A profile MAY restrict ETP
Core. It MUST NOT increase authority, reuse a consumed grant, or report an
ambiguous result as success.

A private profile SHOULD use a reverse-domain prefix controlled by its owner.
An experimental identifier MUST state that it is experimental.

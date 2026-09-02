# HTTP conditional effect profile 0.1

**Status:** Implementer draft
**Identifier:** `effect-transaction/http-conditional/0.1`

This profile defines one conditional HTTP mutation. It binds the mutation to
an origin, request representation, and strong validator. It supports `PUT`,
`PATCH`, and `DELETE` on an origin server that implements HTTP conditional
requests.

## Target identity

`target` MUST be a canonical absolute HTTPS URI. It MUST have an ASCII host
and an explicit path. Query pairs MUST use canonical percent encoding and byte
order. The URI MUST NOT contain user information or a fragment. The executor
MUST NOT follow redirects.

Before it connects, the executor MUST check these values against trusted
policy:

- DNS resolution;
- proxy selection;
- TLS server identity; and
- destination IP addresses.

The executor MUST NOT take these values from model output.

## Profile documents

The arguments document contains the method, media type, selected end-to-end
headers, body digest, and optional idempotency key. When the target supports
an idempotency key, its value MUST equal the ETP `grant_id`.

Model-supplied arguments MUST NOT contain hop-by-hop headers, credentials,
cookies, proxy headers, or conditional headers.

The pre-state document has one of these forms:

```json
{"exists": true, "strong_etag": "..."}
```

```json
{"exists": false}
```

The second form is valid only for a create-only `PUT`. Weak validators are not
permitted.

The resource claim binds the origin, target URI, and method. The expected
effect defines the permitted status class and required postconditions.

## Conditional dispatch

For an existing resource, the executor MUST add one `If-Match` header. Its
value MUST be the committed strong ETag. For a create-only `PUT`, the executor
MUST add `If-None-Match: *`.

The origin MUST evaluate the precondition before it applies the method. An
origin is not conformant if it ignores, removes, or weakens the precondition.

The executor MUST claim the ETP grant before dispatch. It MUST then record the
`dispatch_started` state before the first request byte can leave the executor. This
durable journal update is the dispatch boundary.

An executor can report `not_dispatched` only when it can prove that no request
byte crossed this boundary.

## Receipt rules

- A precondition rejection produces a `failed` receipt.
- An application rejection produces a `failed` receipt.
- A response produces a `succeeded` receipt only after the executor verifies
  all committed postconditions.
- A lost, contradictory, or unverifiable response produces an `unknown`
  receipt.

Some origins report success when a previous request already applied the same
change. That response does not attribute the effect to this grant. Attribution
requires an idempotency key or target transaction identifier. The target and
profile MUST define and validate its semantics. Without that evidence, the
result is `unknown` and requires reconciliation.

## Security considerations and limitations

This profile does not make an arbitrary HTTP API transactional. It does not
define authentication or secure DNS and TLS configuration. It also cannot
prove that an origin implements HTTP correctly.

Do not use this profile for:

- non-idempotent `POST` requests;
- streaming mutations;
- multi-resource transactions; or
- endpoints without an atomic strong precondition.

The URI rules use the generic syntax in
[RFC 3986](https://www.rfc-editor.org/rfc/rfc3986). The conditional rules use
`If-Match` and `If-None-Match` from
[RFC 9110, Section 13](https://www.rfc-editor.org/rfc/rfc9110#section-13).

## Machine-readable contract

`http-conditional-0.1.profile.json` lists the seven profile schemas. The test
vectors are in `../vectors/profiles/`. Run the vectors with:

```sh
node profiles/validate-reference-profiles.mjs
```

[REFERENCE_PROFILES.md](REFERENCE_PROFILES.md) defines the canonical target
encoding.

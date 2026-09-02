# COSE Sign1 and Ed25519 authority profile 0.1

**Status:** Implementer draft
**Identifier:** `effect-transaction/authority/cose-sign1-ed25519/0.1`

This profile authenticates one authority statement about one canonical ETP
record commitment. It uses COSE Sign1 from
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and Ed25519 from
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032). The COSE algorithm mapping
is in [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053). This profile does not
define identity enrollment, PKI, policy, or execution grants.

Normative terms such as MUST and MUST NOT have the meaning defined in RFC 2119
and RFC 8174.

## 1. Wire format

The wire object MUST be a tagged `COSE_Sign1` object as defined by RFC 9052.
It MUST contain an embedded payload. It MUST use CBOR tag 18 in its shortest
encoding. The first encoded byte is `0xd2`.

A verifier MUST reject:

- an untagged object;
- a different tag;
- a non-shortest tag encoding; or
- a detached payload.

The full object and protected header MUST use deterministic CBOR. The rules
are in [RFC 8949, Section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1).
They require definite lengths, shortest integer and length encodings, and
deterministic map-key order.

The outer object has this exact shape:

```text
18([ protected : bstr, {}, payload : bstr, signature : bstr ])
```

The protected map contains these integer labels in deterministic encoded-key
order:

| Label | Name | Required value |
|---|---|---|
| 1 | `alg` | EdDSA (`-8`) |
| 3 | content type | `application/etp-authority+cjson;profile=0.1` |
| 4 | `kid` | UTF-8 bytes equal to payload `key_id` |

The unprotected map MUST be empty. The verifier MUST parse exactly one CBOR
item. It MUST reconstruct the deterministic tagged object and compare its
bytes with the input. This profile does not accept alternate encodings of the
same values.

The signature algorithm is Ed25519. A verifier MUST reject invalid or weak
Ed25519 public keys.

The payload MUST use the ETP canonical JSON encoding. It MUST validate against
`authority-cose-sign1-ed25519-0.1.schema.json`.

The following limits apply:

| Item | Maximum size |
|---|---:|
| Payload | 8,192 bytes |
| COSE object | 16,384 bytes |
| `statement_id` and `key_id` | 256 UTF-8 bytes each |
| `issuer` and `audience` | 512 UTF-8 bytes each |
| `role` and `record_profile` | 256 ASCII bytes each |

`role` and `record_profile` MUST be lowercase ASCII tokens. JSON Schema
`maxLength` counts code points. An implementation MUST also enforce the byte
limits in this section.

## 2. Signed statement

The payload binds these values:

- authority profile and version;
- statement identifier;
- issuer and key identifier;
- authority role and executor audience;
- record profile, version, kind, and canonical digest;
- issue, not-before, and expiry times; and
- authority and configuration epochs.

The COSE external AAD is the canonical JSON encoding of this object:

```json
{
  "authority_profile": "effect-transaction/authority/cose-sign1-ed25519/0.1",
  "authority_profile_version": 1,
  "domain": "effect-transaction/authority/cose-sign1-ed25519/0.1/signature",
  "record_kind": "execution_grant",
  "record_profile": "effect-transaction/core/0.1",
  "record_version": 1
}
```

The last three values are examples. They MUST equal the corresponding payload
values. This binding prevents reuse of a signature under another protocol,
profile, version, or record kind.

`record_digest` MUST be the domain-separated ETP commitment for the complete
record. A transport encoding, display value, tool name, or partial record is
not a valid input.

`statement_id` is an audit identifier. It is not a nonce and does not enforce
single use. A verifier can verify the same statement more than once. ETP
prevents grant replay through the durable atomic claim of the execution grant.

## 3. Current authority state

A valid historical signature is not sufficient. Before the protected
operation, the verifier MUST obtain an authenticated authority snapshot. The
snapshot contains:

- expected issuer and key identifier;
- current Ed25519 public key;
- permitted roles and audiences;
- current authority and configuration epochs;
- key validity limits and optional revocation time; and
- trusted snapshot time.

The call site MUST also supply:

- expected record profile, version, kind, and digest;
- expected role and audience;
- current trusted time; and
- maximum snapshot age.

Verification MUST fail in any of these conditions:

- An exact binding does not match.
- The snapshot is stale or from the future.
- The snapshot time is before statement issuance.
- An epoch does not match.
- The statement or key is outside its validity interval.
- Statement issuance is outside the key validity interval.
- Revocation is effective.

The statement validity interval MUST NOT exceed 300,000 milliseconds. The
configured maximum snapshot age MUST NOT exceed 300,000 milliseconds.

Verification fails if the current snapshot reports revocation or a different
epoch. A current snapshot can invalidate a correctly signed historical
statement.

## 4. Authority roles

Deployments define role tokens. Examples include:

- `commitment_issuer`;
- `policy_evaluator`;
- `execution_authorizer`;
- `effect_observer`; and
- `reconciliation_authority`.

A signing key does not authorize all roles or audiences. The trusted snapshot
MUST authorize both the payload role and audience.

An authority statement authenticates a statement about one record. It does
not replace ETP chain verification. It cannot convert another record type into
an execution grant. The executor MUST still enforce the ETP Core invariants
and the single-use claim.

## 5. Verification procedure

An implementation MUST perform all checks. This sequence is RECOMMENDED:

1. Enforce the input-size limit and decode deterministic COSE.
2. Reject unprotected headers and a missing or detached payload.
3. Parse the payload and reproduce its canonical encoding.
4. Validate the profile identifier and protected header.
5. Resolve the configured issuer and key.
6. Verify Ed25519 over the COSE `Sig_structure` and profile external AAD.
7. Verify snapshot age, key validity, and revocation state.
8. Verify epochs, role, and audience.
9. Verify the expected record profile, version, kind, and digest.
10. Verify the ETP chain and claim the grant atomically.

Data from an unauthenticated payload MUST NOT select or expand a trust root,
issuer, key, role, audience, or record kind.

## 6. Deployment requirements

This profile does not define:

- PKI, enrollment, certificate-path validation, or trust on first use;
- key discovery, key custody, rotation, or revocation delivery;
- trusted-clock construction;
- grant consumption, executor fencing, or atomic dispatch;
- authorization policy; or
- proof that an external effect occurred.

A production host MUST authenticate and durably version the authority
snapshot. It MUST verify the snapshot at the execution boundary. Verification
MUST use the same relevant epoch fence and single-use grant claim. A valid
COSE signature does not provide these properties.

## 7. Test vector

`../vectors/authority-cose-sign1-ed25519-0.1.json` contains one deterministic
interoperability vector. It fixes these inputs and results:

- seed and public key;
- statement and protected header;
- payload and external AAD;
- COSE `Sig_structure`;
- Ed25519 signature; and
- complete tagged `COSE_Sign1` object.

The vector also contains byte-level and binding mutations with stable expected
error codes. Its private key is test data and MUST NOT be used in production.

The Rust test regenerates each byte from the seed. It also rejects each
adversarial mutation under the specified error category. Another
implementation can use the intermediate values to locate an interoperability
error.

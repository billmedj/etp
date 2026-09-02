# ETP authority profile

`effect-transaction-authority` implements the ETP COSE Sign1 and Ed25519
authority profile. It signs the commitment of one ETP record. The assertion is
short-lived and bound to a role and an audience.

The profile uses a tagged `COSE_Sign1` object and Ed25519. It requires
deterministic CBOR. The protected header fixes the algorithm, key identifier,
and ETP content type. The payload is canonical ETP JSON. The external
additional authenticated data binds the authority profile, record profile,
record version, and record kind.

Verification requires two inputs:

1. the signed assertion; and
2. a current `AuthoritySnapshot` from the host.

The snapshot contains the public key, permitted roles and audiences, authority
epochs, key validity interval, revocation state, and observation time. A valid
signature is not sufficient if the current authority state has changed.

## Trust boundary

The crate verifies the signature and all profile bindings. It does not:

- discover keys or establish issuer trust;
- validate certificate paths;
- distribute revocation data;
- provide a trusted clock; or
- make snapshot verification atomic with an effect claim.

The host must obtain `AuthoritySnapshot` from an authenticated source. It must
verify the snapshot immediately before claim and dispatch. If the executor uses
epoch fencing, it must serialize this check with the fence.

`SigningAuthority::from_seed` supports tests and integration. A production
deployment should keep private keys in a signing service or a hardware-backed
key store.

## Verify the crate

```powershell
cargo test --locked -p effect-transaction-authority
cargo clippy --locked -p effect-transaction-authority --all-targets -- -D warnings
cargo run --locked -p effect-transaction-authority --example generate_authority_vector
```

The wire profile and JSON Schema are in
`profiles/authority-cose-sign1-ed25519-0.1.*`. The test
vector contains the protected bytes, payload, external AAD, `Sig_structure`,
signature, tagged envelope, and adversarial mutations.

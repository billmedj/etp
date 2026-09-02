#![forbid(unsafe_code)]

use coset::{CoseSign1, TaggedCborSerializable};
use effect_transaction_authority::{
    AUTHORITY_PROFILE, AuthorityStatement, RecordKind, SigningAuthority, authority_external_aad,
};
use effect_transaction_core::Digest32;
use serde_json::json;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[expect(
    clippy::too_many_lines,
    reason = "the generator writes a complete self-describing interoperability vector"
)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [7_u8; 32];
    let signer =
        SigningAuthority::from_seed("spiffe://example.test/authority", "root-2026-09", seed)?;
    let record_digest = Digest32::from_payload(b"exact canonical ETP execution grant");
    let statement = AuthorityStatement {
        version: 1,
        authority_profile: AUTHORITY_PROFILE.to_owned(),
        statement_id: "authority-assertion-001".to_owned(),
        issuer: "spiffe://example.test/authority".to_owned(),
        key_id: "root-2026-09".to_owned(),
        role: "execution_authorizer".to_owned(),
        audience: "executor:production-a".to_owned(),
        record_profile: "effect-transaction/core/0.1".to_owned(),
        record_version: 1,
        record_kind: RecordKind::ExecutionGrant,
        record_digest: record_digest.clone(),
        issued_at_ms: 1_000_000,
        not_before_ms: 1_000_000,
        expires_at_ms: 1_300_000,
        authority_epoch: 12,
        configuration_epoch: 41,
    };
    let encoded = signer.sign(&statement)?;
    let cose = CoseSign1::from_tagged_slice(&encoded)?;
    let payload = cose
        .payload
        .as_deref()
        .ok_or("generated COSE has no payload")?;
    let protected = cose
        .protected
        .original_data
        .as_deref()
        .ok_or("generated COSE has no protected bytes")?;
    let external_aad = authority_external_aad(&statement)?;
    let sig_structure = cose.tbs_data(&external_aad);

    let vector = json!({
        "profile": AUTHORITY_PROFILE,
        "description": "Deterministic tag-18 COSE Sign1 / Ed25519 authority vector. The seed is test material only.",
        "seed_hex": hex(&seed),
        "public_key_hex": hex(&signer.public_key()),
        "statement": statement,
        "protected_header_hex": hex(protected),
        "payload_hex": hex(payload),
        "external_aad_hex": hex(&external_aad),
        "sig_structure_hex": hex(&sig_structure),
        "signature_hex": hex(&cose.signature),
        "cose_sign1_tagged_hex": hex(&encoded),
        "authority_snapshot": {
            "issuer": "spiffe://example.test/authority",
            "key_id": "root-2026-09",
            "public_key_hex": hex(&signer.public_key()),
            "authorized_roles": ["execution_authorizer"],
            "authorized_audiences": ["executor:production-a"],
            "authority_epoch": 12,
            "configuration_epoch": 41,
            "key_valid_from_ms": 900_000,
            "key_valid_until_ms": 2_000_000,
            "revoked_at_ms": null,
            "observed_at_ms": 1_000_100
        },
        "verification_context": {
            "expected_record_profile": "effect-transaction/core/0.1",
            "expected_record_version": 1,
            "expected_record_kind": "execution_grant",
            "expected_record_digest": record_digest,
            "expected_role": "execution_authorizer",
            "expected_audience": "executor:production-a",
            "now_ms": 1_000_100,
            "maximum_snapshot_age_ms": 1000
        },
        "mutations": [
            {
                "id": "signature_bit_flip",
                "operation": "xor_byte_from_end",
                "offset": 1,
                "mask": 1,
                "expected_error": "invalid_signature"
            },
            {
                "id": "missing_tag_18",
                "operation": "remove_prefix_bytes",
                "count": 1,
                "expected_error": "malformed_cose"
            },
            {
                "id": "wrong_cbor_tag",
                "operation": "replace_prefix_hex",
                "from_hex": "d2",
                "to_hex": "d1",
                "expected_error": "malformed_cose"
            },
            {
                "id": "noncanonical_tag_18",
                "operation": "replace_prefix_hex",
                "from_hex": "d2",
                "to_hex": "d812",
                "expected_error": "noncanonical_cose"
            },
            {
                "id": "trailing_cbor_item",
                "operation": "append_hex",
                "hex": "00",
                "expected_error": "malformed_cose"
            },
            {
                "id": "wrong_expected_audience",
                "operation": "verification_context_override",
                "field": "expected_audience",
                "value": "executor:other",
                "expected_error": "audience_mismatch"
            },
            {
                "id": "issuer_utf8_byte_overflow",
                "operation": "statement_repeat",
                "field": "issuer",
                "value": "é",
                "count": 257,
                "expected_error": "invalid_field"
            }
        ]
    });
    println!("{}", serde_json::to_string_pretty(&vector)?);
    Ok(())
}

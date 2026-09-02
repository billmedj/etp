use std::fs;

use effect_transaction_core::{
    AuthorizationDecision, EffectProposal, EffectReceipt, ExecutionGrant, ProtocolRecord,
    ReconciliationRecord, TaskCommitment, verify_chain, verify_reconciliation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishedVector {
    profile: String,
    description: String,
    transaction: Transaction,
    expected: Expected,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    commitment: TaskCommitment,
    proposal: EffectProposal,
    decision: AuthorizationDecision,
    grant: ExecutionGrant,
    receipt: EffectReceipt,
    reconciliations: Vec<ReconciliationRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    commitment_hash: String,
    proposal_hash: String,
    decision_hash: String,
    grant_hash: String,
    receipt_hash: String,
    reconciliation_hashes: Vec<String>,
    state: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalizationVector {
    profile: String,
    description: String,
    cases: Vec<CanonicalizationCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalizationCase {
    name: String,
    value: Value,
    canonical: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeVector {
    profile: String,
    description: String,
    base: String,
    cases: Vec<NegativeCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeCase {
    name: String,
    pointer: String,
    replacement: Value,
    #[serde(default)]
    also: Vec<Mutation>,
    expected_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    pointer: String,
    replacement: Value,
}

#[test]
fn rust_matches_the_published_typescript_vector() -> Result<(), Box<dyn std::error::Error>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/positive-chain.json"
    );
    let vector: PublishedVector = serde_json::from_slice(&fs::read(path)?)?;
    assert_eq!(vector.profile, "effect-transaction/core/0.1");
    assert!(!vector.description.is_empty());

    let transaction = vector.transaction;
    let verified = verify_chain(
        &transaction.commitment,
        &transaction.proposal,
        &transaction.decision,
        &transaction.grant,
        &transaction.receipt,
    )?;
    assert_eq!(
        verified.commitment_hash.as_str(),
        vector.expected.commitment_hash
    );
    assert_eq!(
        verified.proposal_hash.as_str(),
        vector.expected.proposal_hash
    );
    assert_eq!(
        verified.decision_hash.as_str(),
        vector.expected.decision_hash
    );
    assert_eq!(verified.grant_hash.as_str(), vector.expected.grant_hash);
    assert_eq!(verified.receipt_hash.as_str(), vector.expected.receipt_hash);

    let mut previous: Option<&ReconciliationRecord> = None;
    let mut observed = Vec::new();
    for record in &transaction.reconciliations {
        observed.push(
            verify_reconciliation(&transaction.receipt, previous, record)?
                .as_str()
                .to_owned(),
        );
        previous = Some(record);
    }
    assert_eq!(observed, vector.expected.reconciliation_hashes);
    assert_eq!(vector.expected.state, "effect_confirmed");

    // Direct commitments remain part of the public API, not an implementation detail
    // hidden behind complete-chain verification.
    assert_eq!(
        transaction.commitment.commitment()?.as_str(),
        vector.expected.commitment_hash
    );
    Ok(())
}

#[test]
fn rust_matches_the_published_not_dispatched_vector() -> Result<(), Box<dyn std::error::Error>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/positive-not-dispatched.json"
    );
    let vector: PublishedVector = serde_json::from_slice(&fs::read(path)?)?;
    let transaction = vector.transaction;
    let verified = verify_chain(
        &transaction.commitment,
        &transaction.proposal,
        &transaction.decision,
        &transaction.grant,
        &transaction.receipt,
    )?;
    assert_eq!(verified.receipt_hash.as_str(), vector.expected.receipt_hash);
    assert!(transaction.reconciliations.is_empty());
    assert!(vector.expected.reconciliation_hashes.is_empty());
    assert_eq!(vector.expected.state, "not_dispatched");
    Ok(())
}

#[test]
fn rust_matches_the_published_canonicalization_corpus() -> Result<(), Box<dyn std::error::Error>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/canonicalization.json"
    );
    let vector: CanonicalizationVector = serde_json::from_slice(&fs::read(path)?)?;
    assert_eq!(vector.profile, "effect-transaction/core/0.1");
    assert!(!vector.description.is_empty());
    for case in vector.cases {
        assert_eq!(
            String::from_utf8(effect_transaction_core::canonical_json(&case.value)?)?,
            case.canonical,
            "{}",
            case.name
        );
    }
    Ok(())
}

fn apply_mutation(value: &mut Value, pointer: &str, replacement: Value) -> Result<(), String> {
    if let Some(slot) = value.pointer_mut(pointer) {
        *slot = replacement;
        return Ok(());
    }
    let (parent_pointer, raw_key) = pointer
        .rsplit_once('/')
        .ok_or_else(|| format!("invalid JSON pointer: {pointer}"))?;
    let key = raw_key.replace("~1", "/").replace("~0", "~");
    let parent = value
        .pointer_mut(parent_pointer)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("missing mutation parent: {parent_pointer}"))?;
    parent.insert(key, replacement);
    Ok(())
}

fn verify_transaction_value(value: Value) -> Result<(), Box<dyn std::error::Error>> {
    let transaction: Transaction = serde_json::from_value(value)?;
    verify_chain(
        &transaction.commitment,
        &transaction.proposal,
        &transaction.decision,
        &transaction.grant,
        &transaction.receipt,
    )?;
    let mut previous = None;
    for record in &transaction.reconciliations {
        verify_reconciliation(&transaction.receipt, previous, record)?;
        previous = Some(record);
    }
    Ok(())
}

#[test]
fn rust_rejects_every_published_negative_chain() -> Result<(), Box<dyn std::error::Error>> {
    let vector_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/negative-chains.json"
    );
    let vector: NegativeVector = serde_json::from_slice(&fs::read(vector_path)?)?;
    assert_eq!(vector.profile, "effect-transaction/core/0.1");
    assert!(!vector.description.is_empty());

    let base_path = format!(
        "{}/test-vectors/{}",
        env!("CARGO_MANIFEST_DIR"),
        vector.base
    );
    let base: PublishedVector = serde_json::from_slice(&fs::read(base_path)?)?;
    let base_value = serde_json::to_value(base.transaction)?;
    for case in vector.cases {
        let mut mutated = base_value.clone();
        apply_mutation(&mut mutated, &case.pointer, case.replacement)?;
        for mutation in case.also {
            apply_mutation(&mut mutated, &mutation.pointer, mutation.replacement)?;
        }
        assert!(
            verify_transaction_value(mutated).is_err(),
            "negative case unexpectedly verified: {} ({})",
            case.name,
            case.expected_code
        );
    }
    Ok(())
}

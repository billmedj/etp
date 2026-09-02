//! Records, commitments, and lifecycle rules for one ETP effect.
//!
//! ETP separates an untrusted proposal from an authorization decision, a
//! single-use execution grant, and a recorded outcome.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const PROFILE_VERSION: u64 = 1;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_GRANT_LIFETIME_MS: u64 = 300_000;
pub const MAX_TRANSPORT_INPUT_BYTES: usize = 1_048_576;
pub const MAX_CANONICAL_NESTING_DEPTH: usize = 64;
pub const MAX_CANONICAL_NODES: usize = 100_000;
pub const MAX_RECONCILIATION_RECORDS: usize = 10_000;

const TASK_COMMITMENT_DOMAIN: &str = "effect-transaction/0.1/task-commitment";
const EFFECT_PROPOSAL_DOMAIN: &str = "effect-transaction/0.1/effect-proposal";
const AUTHORIZATION_DECISION_DOMAIN: &str = "effect-transaction/0.1/authorization-decision";
const EXECUTION_GRANT_DOMAIN: &str = "effect-transaction/0.1/execution-grant";
const EFFECT_RECEIPT_DOMAIN: &str = "effect-transaction/0.1/effect-receipt";
const RECONCILIATION_RECORD_DOMAIN: &str = "effect-transaction/0.1/reconciliation-record";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Digest32(String);

impl Digest32 {
    /// Parses the canonical text form of a SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidDigest`] if the value is malformed or all zero.
    pub fn parse(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        validate_digest_text(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Self {
        Self(format_digest(Sha256::digest(payload).into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Allow,
    Deny,
    Review,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    NotDispatched,
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationOutcome {
    EffectConfirmed,
    NoEffectConfirmed,
    PartialEffect,
    StillUnknown,
    Compensated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCommitment {
    pub version: u64,
    pub commitment_id: String,
    pub principal: String,
    pub objective_digest: Digest32,
    pub constraints_digest: Digest32,
    pub authority_scope_digest: Digest32,
    pub policy_epoch: u64,
    pub configuration_epoch: u64,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectProposal {
    pub version: u64,
    pub proposal_id: String,
    pub commitment_hash: Digest32,
    pub effect_profile: String,
    pub operation: String,
    pub target: String,
    pub arguments_digest: Digest32,
    pub expected_effect_digest: Digest32,
    pub pre_state_digest: Digest32,
    pub resource_claim_digest: Digest32,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecision {
    pub version: u64,
    pub decision_id: String,
    pub proposal_hash: Digest32,
    pub evidence_hashes: Vec<Digest32>,
    pub outcome: DecisionOutcome,
    pub reason_codes: Vec<String>,
    pub decided_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGrant {
    pub version: u64,
    pub grant_id: String,
    pub proposal_hash: Digest32,
    pub decision_hash: Digest32,
    pub audience: String,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub uses: u64,
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceipt {
    pub version: u64,
    pub receipt_id: String,
    pub proposal_hash: Digest32,
    pub grant_hash: Digest32,
    pub attempt_id: String,
    pub claimed_at_ms: u64,
    pub dispatched_at_ms: Option<u64>,
    pub completed_at_ms: u64,
    pub outcome: ReceiptOutcome,
    pub observation_digest: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationRecord {
    pub version: u64,
    pub reconciliation_id: String,
    pub receipt_hash: Digest32,
    pub sequence: u64,
    pub parent_reconciliation_hash: Option<Digest32>,
    pub observed_at_ms: u64,
    pub outcome: ReconciliationOutcome,
    pub evidence_digest: Digest32,
}

pub trait ProtocolRecord: Serialize {
    const DOMAIN: &'static str;

    /// Validates the record against the core profile.
    ///
    /// # Errors
    ///
    /// Returns the first validation error.
    fn validate(&self) -> Result<(), ProtocolError>;

    /// Validates the record and computes its domain-separated commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, serialization, or canonicalization fails.
    fn commitment(&self) -> Result<Digest32, ProtocolError> {
        self.validate()?;
        hash_record(Self::DOMAIN, self)
    }
}

impl ProtocolRecord for TaskCommitment {
    const DOMAIN: &'static str = TASK_COMMITMENT_DOMAIN;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_version(self.version)?;
        validate_identifier("commitment_id", &self.commitment_id)?;
        validate_trimmed_text("principal", &self.principal, 512)?;
        validate_safe_integer("policy_epoch", self.policy_epoch)?;
        validate_safe_integer("configuration_epoch", self.configuration_epoch)?;
        validate_window(self.created_at_ms, self.expires_at_ms)
    }
}

impl ProtocolRecord for EffectProposal {
    const DOMAIN: &'static str = EFFECT_PROPOSAL_DOMAIN;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_version(self.version)?;
        validate_identifier("proposal_id", &self.proposal_id)?;
        validate_trimmed_text("effect_profile", &self.effect_profile, 256)?;
        validate_token("operation", &self.operation)?;
        validate_trimmed_text("target", &self.target, 4_096)?;
        validate_window(self.created_at_ms, self.expires_at_ms)
    }
}

impl ProtocolRecord for AuthorizationDecision {
    const DOMAIN: &'static str = AUTHORIZATION_DECISION_DOMAIN;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_version(self.version)?;
        validate_identifier("decision_id", &self.decision_id)?;
        validate_sorted_unique_digests(&self.evidence_hashes, 256)?;
        validate_sorted_unique_tokens("reason_codes", &self.reason_codes, 64)?;
        if self.reason_codes.is_empty() {
            return Err(ProtocolError::MissingReasonCode);
        }
        validate_window(self.decided_at_ms, self.expires_at_ms)?;
        if self.outcome == DecisionOutcome::Allow && self.evidence_hashes.is_empty() {
            return Err(ProtocolError::MissingAuthorizingEvidence);
        }
        Ok(())
    }
}

impl ProtocolRecord for ExecutionGrant {
    const DOMAIN: &'static str = EXECUTION_GRANT_DOMAIN;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_version(self.version)?;
        validate_identifier("grant_id", &self.grant_id)?;
        validate_trimmed_text("audience", &self.audience, 512)?;
        validate_nonce(&self.nonce)?;
        if self.uses != 1 {
            return Err(ProtocolError::GrantMustBeSingleUse);
        }
        validate_window(self.not_before_ms, self.expires_at_ms)?;
        if self.expires_at_ms - self.not_before_ms > MAX_GRANT_LIFETIME_MS {
            return Err(ProtocolError::GrantLifetimeExceeded);
        }
        Ok(())
    }
}

impl ProtocolRecord for EffectReceipt {
    const DOMAIN: &'static str = EFFECT_RECEIPT_DOMAIN;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_version(self.version)?;
        validate_identifier("receipt_id", &self.receipt_id)?;
        validate_identifier("attempt_id", &self.attempt_id)?;
        validate_safe_integer("claimed_at_ms", self.claimed_at_ms)?;
        validate_safe_integer("completed_at_ms", self.completed_at_ms)?;
        if self.claimed_at_ms > self.completed_at_ms {
            return Err(ProtocolError::InvalidReceiptTimeline);
        }
        if let Some(dispatched_at_ms) = self.dispatched_at_ms {
            validate_safe_integer("dispatched_at_ms", dispatched_at_ms)?;
            if dispatched_at_ms < self.claimed_at_ms || dispatched_at_ms > self.completed_at_ms {
                return Err(ProtocolError::InvalidReceiptTimeline);
            }
        }
        match (self.outcome, self.dispatched_at_ms) {
            (ReceiptOutcome::NotDispatched, Some(_)) => {
                Err(ProtocolError::ContradictoryDispatchEvidence)
            }
            (ReceiptOutcome::Succeeded | ReceiptOutcome::Failed, None) => {
                Err(ProtocolError::MissingDispatchEvidence)
            }
            _ => Ok(()),
        }
    }
}

impl ProtocolRecord for ReconciliationRecord {
    const DOMAIN: &'static str = RECONCILIATION_RECORD_DOMAIN;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_version(self.version)?;
        validate_identifier("reconciliation_id", &self.reconciliation_id)?;
        validate_safe_integer("observed_at_ms", self.observed_at_ms)?;
        if self.sequence == 0 || self.sequence > MAX_SAFE_INTEGER {
            return Err(ProtocolError::InvalidSequence);
        }
        if (self.sequence == 1) != self.parent_reconciliation_hash.is_none() {
            return Err(ProtocolError::InvalidReconciliationParent);
        }
        Ok(())
    }
}

/// An ETP record bundle at a valid lifecycle stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionBundle {
    pub commitment: TaskCommitment,
    pub proposal: EffectProposal,
    pub decision: AuthorizationDecision,
    pub grant: Option<ExecutionGrant>,
    pub receipt: Option<EffectReceipt>,
    #[serde(default)]
    pub reconciliations: Vec<ReconciliationRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Decided,
    Granted,
    NotDispatched,
    Succeeded,
    Failed,
    Unknown,
    EffectConfirmed,
    NoEffectConfirmed,
    PartialEffect,
    StillUnknown,
    Compensated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedTransaction {
    pub commitment_hash: Digest32,
    pub proposal_hash: Digest32,
    pub decision_hash: Digest32,
    pub grant_hash: Option<Digest32>,
    pub receipt_hash: Option<Digest32>,
    pub reconciliation_hashes: Vec<Digest32>,
    pub state: TransactionState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDecision {
    pub commitment_hash: Digest32,
    pub proposal_hash: Digest32,
    pub decision_hash: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedChain {
    pub commitment_hash: Digest32,
    pub proposal_hash: Digest32,
    pub decision_hash: Digest32,
    pub grant_hash: Digest32,
    pub receipt_hash: Digest32,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedAuthorization {
    commitment_hash: Digest32,
    proposal_hash: Digest32,
    decision_hash: Digest32,
    grant_hash: Digest32,
}

/// Verifies the records from the task commitment through the decision.
///
/// A `deny` or `review` decision is valid, but it cannot produce a grant.
///
/// # Errors
///
/// Returns an error for an invalid record, link, or validity interval.
pub fn verify_decision(
    commitment: &TaskCommitment,
    proposal: &EffectProposal,
    decision: &AuthorizationDecision,
) -> Result<VerifiedDecision, ProtocolError> {
    let commitment_hash = commitment.commitment()?;
    if proposal.commitment_hash != commitment_hash {
        return Err(ProtocolError::ChainMismatch("commitment_hash"));
    }
    if proposal.created_at_ms < commitment.created_at_ms
        || proposal.expires_at_ms > commitment.expires_at_ms
    {
        return Err(ProtocolError::InvalidNestedWindow("proposal"));
    }

    let proposal_hash = proposal.commitment()?;
    if decision.proposal_hash != proposal_hash {
        return Err(ProtocolError::ChainMismatch("decision.proposal_hash"));
    }
    if decision.decided_at_ms < proposal.created_at_ms
        || decision.expires_at_ms > proposal.expires_at_ms
    {
        return Err(ProtocolError::InvalidNestedWindow("decision"));
    }

    Ok(VerifiedDecision {
        commitment_hash,
        proposal_hash,
        decision_hash: decision.commitment()?,
    })
}

fn verify_authorization(
    commitment: &TaskCommitment,
    proposal: &EffectProposal,
    decision: &AuthorizationDecision,
    grant: &ExecutionGrant,
) -> Result<VerifiedAuthorization, ProtocolError> {
    let verified = verify_decision(commitment, proposal, decision)?;
    if decision.outcome != DecisionOutcome::Allow {
        return Err(ProtocolError::DecisionDoesNotAuthorize);
    }

    if grant.proposal_hash != verified.proposal_hash {
        return Err(ProtocolError::ChainMismatch("grant.proposal_hash"));
    }
    if grant.decision_hash != verified.decision_hash {
        return Err(ProtocolError::ChainMismatch("grant.decision_hash"));
    }
    if grant.not_before_ms < decision.decided_at_ms || grant.expires_at_ms > decision.expires_at_ms
    {
        return Err(ProtocolError::InvalidNestedWindow("grant"));
    }

    let grant_hash = grant.commitment()?;
    Ok(VerifiedAuthorization {
        commitment_hash: verified.commitment_hash,
        proposal_hash: verified.proposal_hash,
        decision_hash: verified.decision_hash,
        grant_hash,
    })
}

/// Verifies the records from the task commitment through the execution grant.
///
/// # Errors
///
/// Returns an error for an invalid record, link, validity interval, or decision.
pub fn verify_grant(
    commitment: &TaskCommitment,
    proposal: &EffectProposal,
    decision: &AuthorizationDecision,
    grant: &ExecutionGrant,
) -> Result<Digest32, ProtocolError> {
    Ok(verify_authorization(commitment, proposal, decision, grant)?.grant_hash)
}

/// Verifies the records from the task commitment through the effect receipt.
///
/// # Errors
///
/// Returns an error for an invalid record, link, time interval, decision, or claim.
pub fn verify_chain(
    commitment: &TaskCommitment,
    proposal: &EffectProposal,
    decision: &AuthorizationDecision,
    grant: &ExecutionGrant,
    receipt: &EffectReceipt,
) -> Result<VerifiedChain, ProtocolError> {
    let authorization = verify_authorization(commitment, proposal, decision, grant)?;
    if receipt.proposal_hash != authorization.proposal_hash {
        return Err(ProtocolError::ChainMismatch("receipt.proposal_hash"));
    }
    if receipt.grant_hash != authorization.grant_hash {
        return Err(ProtocolError::ChainMismatch("receipt.grant_hash"));
    }
    if receipt.claimed_at_ms < grant.not_before_ms || receipt.claimed_at_ms >= grant.expires_at_ms {
        return Err(ProtocolError::ReceiptOutsideGrantWindow);
    }

    let receipt_hash = receipt.commitment()?;
    Ok(VerifiedChain {
        commitment_hash: authorization.commitment_hash,
        proposal_hash: authorization.proposal_hash,
        decision_hash: authorization.decision_hash,
        grant_hash: authorization.grant_hash,
        receipt_hash,
    })
}

/// Verifies one reconciliation transition.
///
/// # Errors
///
/// Returns an error if the receipt is not `unknown`, the parent or sequence is
/// invalid, time moves backward, or the prior result is terminal.
pub fn verify_reconciliation(
    receipt: &EffectReceipt,
    previous: Option<&ReconciliationRecord>,
    record: &ReconciliationRecord,
) -> Result<Digest32, ProtocolError> {
    if receipt.outcome != ReceiptOutcome::Unknown {
        return Err(ProtocolError::ReconciliationRequiresUnknown);
    }
    let receipt_hash = receipt.commitment()?;
    if record.receipt_hash != receipt_hash {
        return Err(ProtocolError::ChainMismatch("reconciliation.receipt_hash"));
    }
    if record.observed_at_ms < receipt.completed_at_ms {
        return Err(ProtocolError::InvalidReconciliationTimeline);
    }
    match previous {
        None => {
            if record.sequence != 1 || record.parent_reconciliation_hash.is_some() {
                return Err(ProtocolError::InvalidReconciliationParent);
            }
        }
        Some(parent) => {
            if matches!(
                parent.outcome,
                ReconciliationOutcome::EffectConfirmed
                    | ReconciliationOutcome::NoEffectConfirmed
                    | ReconciliationOutcome::Compensated
            ) {
                return Err(ProtocolError::ReconciliationAlreadyTerminal);
            }
            let parent_hash = parent.commitment()?;
            if record.sequence != parent.sequence.saturating_add(1)
                || record.parent_reconciliation_hash.as_ref() != Some(&parent_hash)
                || record.receipt_hash != parent.receipt_hash
                || record.observed_at_ms < parent.observed_at_ms
            {
                return Err(ProtocolError::InvalidReconciliationParent);
            }
        }
    }
    record.commitment()
}

/// Verifies a transaction bundle and returns its commitments and state.
///
/// # Errors
///
/// Returns an error if a record, link, lifecycle stage, receipt, or
/// reconciliation transition is invalid.
pub fn verify_transaction(
    bundle: &TransactionBundle,
) -> Result<VerifiedTransaction, ProtocolError> {
    if bundle.reconciliations.len() > MAX_RECONCILIATION_RECORDS {
        return Err(ProtocolError::ResourceLimit("reconciliation records"));
    }

    let decision = verify_decision(&bundle.commitment, &bundle.proposal, &bundle.decision)?;
    let Some(grant) = bundle.grant.as_ref() else {
        if bundle.receipt.is_some() || !bundle.reconciliations.is_empty() {
            return Err(ProtocolError::MissingPredecessor("grant"));
        }
        return Ok(VerifiedTransaction {
            commitment_hash: decision.commitment_hash,
            proposal_hash: decision.proposal_hash,
            decision_hash: decision.decision_hash,
            grant_hash: None,
            receipt_hash: None,
            reconciliation_hashes: Vec::new(),
            state: TransactionState::Decided,
        });
    };

    let grant_hash = verify_grant(
        &bundle.commitment,
        &bundle.proposal,
        &bundle.decision,
        grant,
    )?;
    let Some(receipt) = bundle.receipt.as_ref() else {
        if !bundle.reconciliations.is_empty() {
            return Err(ProtocolError::MissingPredecessor("receipt"));
        }
        return Ok(VerifiedTransaction {
            commitment_hash: decision.commitment_hash,
            proposal_hash: decision.proposal_hash,
            decision_hash: decision.decision_hash,
            grant_hash: Some(grant_hash),
            receipt_hash: None,
            reconciliation_hashes: Vec::new(),
            state: TransactionState::Granted,
        });
    };

    let chain = verify_chain(
        &bundle.commitment,
        &bundle.proposal,
        &bundle.decision,
        grant,
        receipt,
    )?;
    let mut reconciliation_hashes = Vec::with_capacity(bundle.reconciliations.len());
    let mut previous: Option<&ReconciliationRecord> = None;
    let mut identifiers = std::collections::HashSet::new();
    for record in &bundle.reconciliations {
        if !identifiers.insert(record.reconciliation_id.as_str()) {
            return Err(ProtocolError::DuplicateIdentifier("reconciliation_id"));
        }
        reconciliation_hashes.push(verify_reconciliation(receipt, previous, record)?);
        previous = Some(record);
    }

    let state = previous.map_or_else(
        || match receipt.outcome {
            ReceiptOutcome::NotDispatched => TransactionState::NotDispatched,
            ReceiptOutcome::Succeeded => TransactionState::Succeeded,
            ReceiptOutcome::Failed => TransactionState::Failed,
            ReceiptOutcome::Unknown => TransactionState::Unknown,
        },
        |record| match record.outcome {
            ReconciliationOutcome::EffectConfirmed => TransactionState::EffectConfirmed,
            ReconciliationOutcome::NoEffectConfirmed => TransactionState::NoEffectConfirmed,
            ReconciliationOutcome::PartialEffect => TransactionState::PartialEffect,
            ReconciliationOutcome::StillUnknown => TransactionState::StillUnknown,
            ReconciliationOutcome::Compensated => TransactionState::Compensated,
        },
    );

    Ok(VerifiedTransaction {
        commitment_hash: chain.commitment_hash,
        proposal_hash: chain.proposal_hash,
        decision_hash: chain.decision_hash,
        grant_hash: Some(chain.grant_hash),
        receipt_hash: Some(chain.receipt_hash),
        reconciliation_hashes,
        state,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantClaim {
    pub grant_id: String,
    pub grant_hash: Digest32,
    pub attempt_id: String,
    pub claimed_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantClaimRequest {
    pub attempt_id: String,
    pub expected_audience: String,
    pub observed_policy_epoch: u64,
    pub observed_configuration_epoch: u64,
    pub observed_pre_state_digest: Digest32,
    pub observed_resource_claim_digest: Digest32,
    pub revoked: bool,
}

impl GrantClaimRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        validate_identifier("attempt_id", &self.attempt_id)?;
        validate_trimmed_text("expected_audience", &self.expected_audience, 512)?;
        validate_safe_integer("observed_policy_epoch", self.observed_policy_epoch)?;
        validate_safe_integer(
            "observed_configuration_epoch",
            self.observed_configuration_epoch,
        )
    }
}

pub trait TrustedClock {
    fn now_ms(&self) -> Option<u64>;
}

#[derive(Clone, Debug)]
struct StoredGrant {
    hash: Digest32,
    commitment: TaskCommitment,
    proposal: EffectProposal,
    decision: AuthorizationDecision,
    grant: ExecutionGrant,
    claim: Option<GrantClaim>,
    receipt: Option<EffectReceipt>,
    reconciliations: Vec<ReconciliationRecord>,
}

#[derive(Debug, Default)]
struct MemoryGrantState {
    grants: HashMap<String, StoredGrant>,
    grant_by_hash: HashMap<Digest32, String>,
    grant_by_proposal: HashMap<Digest32, String>,
    grant_by_decision: HashMap<Digest32, String>,
    grant_by_receipt: HashMap<Digest32, String>,
    last_trusted_time_ms: Option<u64>,
}

#[derive(Debug, Default)]
pub struct MemoryGrantStore {
    state: Mutex<MemoryGrantState>,
}

impl MemoryGrantStore {
    /// Registers one grant for a proposal and decision.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization chain is invalid or if the grant,
    /// proposal, or decision conflicts with a prior registration.
    pub fn register(
        &self,
        commitment: &TaskCommitment,
        proposal: &EffectProposal,
        decision: &AuthorizationDecision,
        grant: &ExecutionGrant,
    ) -> Result<Digest32, ProtocolError> {
        let verified = verify_authorization(commitment, proposal, decision, grant)?;
        let grant_hash = verified.grant_hash;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| ProtocolError::StoreUnavailable)?;
        if guard.grants.contains_key(&grant.grant_id) {
            return Err(ProtocolError::DuplicateGrant);
        }
        if guard
            .grant_by_decision
            .contains_key(&verified.decision_hash)
        {
            return Err(ProtocolError::DecisionAlreadyGranted);
        }
        if guard
            .grant_by_proposal
            .contains_key(&verified.proposal_hash)
        {
            return Err(ProtocolError::ProposalAlreadyGranted);
        }
        guard.grants.insert(
            grant.grant_id.clone(),
            StoredGrant {
                hash: grant_hash.clone(),
                commitment: commitment.clone(),
                proposal: proposal.clone(),
                decision: decision.clone(),
                grant: grant.clone(),
                claim: None,
                receipt: None,
                reconciliations: Vec::new(),
            },
        );
        guard
            .grant_by_hash
            .insert(grant_hash.clone(), grant.grant_id.clone());
        guard
            .grant_by_decision
            .insert(verified.decision_hash, grant.grant_id.clone());
        guard
            .grant_by_proposal
            .insert(verified.proposal_hash, grant.grant_id.clone());
        Ok(grant_hash)
    }

    /// Atomically claims a registered grant against a currentness snapshot.
    ///
    /// # Errors
    ///
    /// This in-memory store does not authenticate the snapshot. It also does not
    /// serialize external state changes with the claim. Production callers must
    /// obtain the snapshot from a trusted source under the profile's consistency
    /// or fencing boundary.
    ///
    /// Returns an error for a clock failure, clock rollback, stale or revoked
    /// authority, audience mismatch, invalid time, or prior claim.
    pub fn claim(
        &self,
        grant: &ExecutionGrant,
        request: &GrantClaimRequest,
        clock: &impl TrustedClock,
    ) -> Result<GrantClaim, ProtocolError> {
        request.validate()?;
        let now_ms = clock.now_ms().ok_or(ProtocolError::ClockUnavailable)?;
        validate_safe_integer("trusted now_ms", now_ms)?;
        let supplied_hash = grant.commitment()?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| ProtocolError::StoreUnavailable)?;
        if guard
            .last_trusted_time_ms
            .is_some_and(|last_seen| now_ms < last_seen)
        {
            return Err(ProtocolError::ClockRollback);
        }
        guard.last_trusted_time_ms = Some(now_ms);
        let stored = guard
            .grants
            .get_mut(&grant.grant_id)
            .ok_or(ProtocolError::UnknownGrant)?;
        if stored.hash != supplied_hash {
            return Err(ProtocolError::ChainMismatch("stored grant"));
        }
        let verified = verify_authorization(
            &stored.commitment,
            &stored.proposal,
            &stored.decision,
            &stored.grant,
        )?;
        if verified.grant_hash != stored.hash {
            return Err(ProtocolError::ChainMismatch("registered authorization"));
        }
        if request.expected_audience != stored.grant.audience {
            return Err(ProtocolError::AudienceMismatch);
        }
        if request.observed_policy_epoch != stored.commitment.policy_epoch
            || request.observed_configuration_epoch != stored.commitment.configuration_epoch
        {
            return Err(ProtocolError::StaleAuthority);
        }
        if request.observed_pre_state_digest != stored.proposal.pre_state_digest {
            return Err(ProtocolError::StalePreState);
        }
        if request.observed_resource_claim_digest != stored.proposal.resource_claim_digest {
            return Err(ProtocolError::StaleResourceClaim);
        }
        if request.revoked {
            return Err(ProtocolError::GrantRevoked);
        }
        if now_ms < stored.grant.not_before_ms {
            return Err(ProtocolError::GrantNotYetValid);
        }
        if now_ms >= stored.grant.expires_at_ms {
            return Err(ProtocolError::GrantExpired);
        }
        if stored.claim.is_some() {
            return Err(ProtocolError::GrantAlreadyClaimed);
        }
        let claim = GrantClaim {
            grant_id: grant.grant_id.clone(),
            grant_hash: stored.hash.clone(),
            attempt_id: request.attempt_id.clone(),
            claimed_at_ms: now_ms,
        };
        stored.claim = Some(claim.clone());
        Ok(claim)
    }

    /// Records the ledger receipt for the winning attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or unclaimed grant, an attempt mismatch,
    /// an invalid chain, or a conflicting receipt.
    pub fn record_receipt(&self, receipt: &EffectReceipt) -> Result<Digest32, ProtocolError> {
        receipt.validate()?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| ProtocolError::StoreUnavailable)?;
        let grant_id = guard
            .grant_by_hash
            .get(&receipt.grant_hash)
            .cloned()
            .ok_or(ProtocolError::UnknownGrant)?;
        let stored = guard
            .grants
            .get_mut(&grant_id)
            .ok_or(ProtocolError::UnknownGrant)?;
        let claim = stored
            .claim
            .as_ref()
            .ok_or(ProtocolError::ReceiptWithoutClaim)?;
        if receipt.attempt_id != claim.attempt_id || receipt.claimed_at_ms != claim.claimed_at_ms {
            return Err(ProtocolError::ReceiptClaimMismatch);
        }
        let verified = verify_chain(
            &stored.commitment,
            &stored.proposal,
            &stored.decision,
            &stored.grant,
            receipt,
        )?;
        if let Some(existing) = &stored.receipt {
            if existing.commitment()? == verified.receipt_hash {
                return Ok(verified.receipt_hash);
            }
            return Err(ProtocolError::ReceiptAlreadyRecorded);
        }
        stored.receipt = Some(receipt.clone());
        guard
            .grant_by_receipt
            .insert(verified.receipt_hash.clone(), grant_id);
        Ok(verified.receipt_hash)
    }

    /// Appends one reconciliation record.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown receipt, invalid link, duplicate
    /// identifier, terminal extension, fork, or resource limit.
    pub fn append_reconciliation(
        &self,
        record: &ReconciliationRecord,
    ) -> Result<Digest32, ProtocolError> {
        record.validate()?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| ProtocolError::StoreUnavailable)?;
        let grant_id = guard
            .grant_by_receipt
            .get(&record.receipt_hash)
            .cloned()
            .ok_or(ProtocolError::UnknownReceipt)?;
        let stored = guard
            .grants
            .get_mut(&grant_id)
            .ok_or(ProtocolError::UnknownGrant)?;
        let receipt = stored
            .receipt
            .as_ref()
            .ok_or(ProtocolError::UnknownReceipt)?;
        if record.sequence <= stored.reconciliations.len() as u64 {
            let index =
                usize::try_from(record.sequence - 1).map_err(|_| ProtocolError::InvalidSequence)?;
            let existing = stored
                .reconciliations
                .get(index)
                .ok_or(ProtocolError::InvalidSequence)?;
            let existing_hash = existing.commitment()?;
            if existing_hash == record.commitment()? {
                return Ok(existing_hash);
            }
            return Err(ProtocolError::ReconciliationFork);
        }
        if stored.reconciliations.len() >= MAX_RECONCILIATION_RECORDS {
            return Err(ProtocolError::ResourceLimit("reconciliation records"));
        }
        if stored
            .reconciliations
            .iter()
            .any(|existing| existing.reconciliation_id == record.reconciliation_id)
        {
            return Err(ProtocolError::DuplicateIdentifier("reconciliation_id"));
        }
        let previous = stored.reconciliations.last();
        let hash = verify_reconciliation(receipt, previous, record)?;
        stored.reconciliations.push(record.clone());
        Ok(hash)
    }
}

/// Encodes a value as bounded canonical ETP JSON.
///
/// # Errors
///
/// Returns an error for an unsupported number, a serialization failure, or an
/// exceeded depth or node limit.
pub fn canonical_json<T: Serialize + ?Sized>(record: &T) -> Result<Vec<u8>, ProtocolError> {
    let value = serde_json::to_value(record).map_err(ProtocolError::Json)?;
    let mut nodes = 0;
    validate_value_budget(&value, 1, &mut nodes)?;
    let mut output = String::new();
    encode_canonical_value(&value, &mut output)?;
    Ok(output.into_bytes())
}

/// Parses and validates one ETP record from untrusted JSON bytes.
///
/// # Errors
///
/// Returns an error for oversized input, malformed or duplicate fields,
/// trailing data, a validation failure, or a canonicalization limit.
pub fn parse_record<T>(input: &[u8]) -> Result<T, ProtocolError>
where
    T: DeserializeOwned + ProtocolRecord,
{
    if input.len() > MAX_TRANSPORT_INPUT_BYTES {
        return Err(ProtocolError::ResourceLimit("transport bytes"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let record = T::deserialize(&mut deserializer).map_err(ProtocolError::Json)?;
    deserializer.end().map_err(ProtocolError::Json)?;
    record.validate()?;
    let _ = canonical_json(&record)?;
    Ok(record)
}

/// Parses and verifies an ETP transaction bundle.
///
/// # Errors
///
/// Returns an error for oversized or malformed JSON, duplicate or unknown
/// fields, invalid records, invalid links, or an invalid lifecycle stage.
pub fn parse_transaction_bundle(input: &[u8]) -> Result<TransactionBundle, ProtocolError> {
    if input.len() > MAX_TRANSPORT_INPUT_BYTES {
        return Err(ProtocolError::ResourceLimit("transport bytes"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let bundle = TransactionBundle::deserialize(&mut deserializer).map_err(ProtocolError::Json)?;
    deserializer.end().map_err(ProtocolError::Json)?;
    let _ = verify_transaction(&bundle)?;
    Ok(bundle)
}

fn validate_value_budget(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ProtocolError> {
    if depth > MAX_CANONICAL_NESTING_DEPTH {
        return Err(ProtocolError::ResourceLimit("JSON nesting depth"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or(ProtocolError::ResourceLimit("JSON nodes"))?;
    if *nodes > MAX_CANONICAL_NODES {
        return Err(ProtocolError::ResourceLimit("JSON nodes"));
    }
    match value {
        Value::Array(values) => {
            for child in values {
                validate_value_budget(child, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for child in values.values() {
                validate_value_budget(child, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn hash_record<T: Serialize + ?Sized>(domain: &str, record: &T) -> Result<Digest32, ProtocolError> {
    let canonical = canonical_json(record)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    Ok(Digest32(format_digest(hasher.finalize().into())))
}

fn encode_canonical_value(value: &Value, output: &mut String) -> Result<(), ProtocolError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => {
            if let Some(number) = value.as_i64() {
                let magnitude = number.unsigned_abs();
                if magnitude > MAX_SAFE_INTEGER {
                    return Err(ProtocolError::UnsafeJsonNumber);
                }
                output.push_str(&number.to_string());
            } else if let Some(number) = value.as_u64() {
                if number > MAX_SAFE_INTEGER {
                    return Err(ProtocolError::UnsafeJsonNumber);
                }
                output.push_str(&number.to_string());
            } else {
                return Err(ProtocolError::UnsafeJsonNumber);
            }
        }
        Value::String(value) => {
            let encoded = serde_json::to_string(value).map_err(ProtocolError::Json)?;
            output.push_str(&encoded);
        }
        Value::Array(values) => {
            output.push('[');
            for (index, child) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                encode_canonical_value(child, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            let ordered: BTreeMap<&str, &Value> = values
                .iter()
                .map(|(key, child)| (key.as_str(), child))
                .collect();
            output.push('{');
            for (index, (key, child)) in ordered.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                let encoded_key = serde_json::to_string(key).map_err(ProtocolError::Json)?;
                output.push_str(&encoded_key);
                output.push(':');
                encode_canonical_value(child, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn validate_version(version: u64) -> Result<(), ProtocolError> {
    if version == PROFILE_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion(version))
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    validate_trimmed_text(field, value, 256)
}

fn validate_trimmed_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ProtocolError> {
    validate_nonempty_text(field, value, maximum_bytes)?;
    if value.trim() != value {
        return Err(ProtocolError::InvalidBinding(field));
    }
    Ok(())
}

fn validate_nonempty_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        Err(ProtocolError::InvalidBinding(field))
    } else {
        Ok(())
    }
}

fn validate_token(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    validate_trimmed_text(field, value, 256)?;
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(b'a'..=b'z'))
        || !bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'/' | b'-'
            )
        })
    {
        return Err(ProtocolError::InvalidToken(field));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), ProtocolError> {
    if !(22..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
    {
        return Err(ProtocolError::InvalidNonce);
    }
    Ok(())
}

fn validate_window(start: u64, end: u64) -> Result<(), ProtocolError> {
    validate_safe_integer("window start", start)?;
    validate_safe_integer("window end", end)?;
    if start >= end {
        Err(ProtocolError::InvalidTimeWindow)
    } else {
        Ok(())
    }
}

fn validate_safe_integer(field: &'static str, value: u64) -> Result<(), ProtocolError> {
    if value > MAX_SAFE_INTEGER {
        Err(ProtocolError::UnsafeInteger(field))
    } else {
        Ok(())
    }
}

fn validate_sorted_unique_digests(
    values: &[Digest32],
    maximum_items: usize,
) -> Result<(), ProtocolError> {
    if values.len() > maximum_items {
        return Err(ProtocolError::ListTooLong("evidence_hashes"));
    }
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(ProtocolError::NonCanonicalList("evidence_hashes"));
    }
    Ok(())
}

fn validate_sorted_unique_tokens(
    field: &'static str,
    values: &[String],
    maximum_items: usize,
) -> Result<(), ProtocolError> {
    if values.len() > maximum_items {
        return Err(ProtocolError::ListTooLong(field));
    }
    for value in values {
        validate_token(field, value)?;
    }
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(ProtocolError::NonCanonicalList(field));
    }
    Ok(())
}

fn validate_digest_text(value: &str) -> Result<(), ProtocolError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ProtocolError::InvalidDigest);
    };
    if hex.len() != 64
        || hex
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || hex.bytes().all(|byte| byte == b'0')
    {
        return Err(ProtocolError::InvalidDigest);
    }
    Ok(())
}

fn format_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("JSON processing failed: {0}")]
    Json(serde_json::Error),
    #[error("unsupported profile version {0}")]
    UnsupportedVersion(u64),
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid binding: {0}")]
    InvalidBinding(&'static str),
    #[error("duplicate identifier: {0}")]
    DuplicateIdentifier(&'static str),
    #[error("invalid token: {0}")]
    InvalidToken(&'static str),
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("integer is outside the interoperable JSON range: {0}")]
    UnsafeInteger(&'static str),
    #[error("JSON number is outside the interoperable range")]
    UnsafeJsonNumber,
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("invalid time window")]
    InvalidTimeWindow,
    #[error("invalid nested time window: {0}")]
    InvalidNestedWindow(&'static str),
    #[error("non-canonical list: {0}")]
    NonCanonicalList(&'static str),
    #[error("list exceeds profile limit: {0}")]
    ListTooLong(&'static str),
    #[error("authorization decision requires a reason code")]
    MissingReasonCode,
    #[error("allow decision requires admitted evidence")]
    MissingAuthorizingEvidence,
    #[error("execution grant must have exactly one use")]
    GrantMustBeSingleUse,
    #[error("execution grant lifetime exceeds the core profile limit")]
    GrantLifetimeExceeded,
    #[error("invalid receipt timeline")]
    InvalidReceiptTimeline,
    #[error("dispatched effect cannot have a not_dispatched outcome")]
    ContradictoryDispatchEvidence,
    #[error("known effect outcome requires a dispatch timestamp")]
    MissingDispatchEvidence,
    #[error("invalid reconciliation sequence")]
    InvalidSequence,
    #[error("invalid reconciliation parent")]
    InvalidReconciliationParent,
    #[error("reconciliation observation predates receipt completion")]
    InvalidReconciliationTimeline,
    #[error("terminal reconciliation cannot be extended")]
    ReconciliationAlreadyTerminal,
    #[error("record chain mismatch: {0}")]
    ChainMismatch(&'static str),
    #[error("record chain is missing a required predecessor: {0}")]
    MissingPredecessor(&'static str),
    #[error("decision does not authorize execution")]
    DecisionDoesNotAuthorize,
    #[error("receipt claim is outside the grant window")]
    ReceiptOutsideGrantWindow,
    #[error("only an unknown receipt can be reconciled")]
    ReconciliationRequiresUnknown,
    #[error("grant store is unavailable")]
    StoreUnavailable,
    #[error("trusted clock is unavailable")]
    ClockUnavailable,
    #[error("trusted clock moved backwards")]
    ClockRollback,
    #[error("duplicate grant")]
    DuplicateGrant,
    #[error("authorization decision already issued a grant")]
    DecisionAlreadyGranted,
    #[error("effect proposal already received a grant")]
    ProposalAlreadyGranted,
    #[error("unknown grant")]
    UnknownGrant,
    #[error("receipt requires a successful claim")]
    ReceiptWithoutClaim,
    #[error("receipt attempt does not match the winning claim")]
    ReceiptClaimMismatch,
    #[error("ledger receipt is already recorded for this attempt")]
    ReceiptAlreadyRecorded,
    #[error("unknown receipt")]
    UnknownReceipt,
    #[error("reconciliation would fork the authoritative history")]
    ReconciliationFork,
    #[error("grant audience does not match the claiming executor")]
    AudienceMismatch,
    #[error("policy or configuration authority is stale")]
    StaleAuthority,
    #[error("target pre-state is stale")]
    StalePreState,
    #[error("resource claim is stale")]
    StaleResourceClaim,
    #[error("grant is revoked")]
    GrantRevoked,
    #[error("grant is not yet valid")]
    GrantNotYetValid,
    #[error("grant expired")]
    GrantExpired,
    #[error("grant was already claimed")]
    GrantAlreadyClaimed,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, RngSeed};

    use super::*;

    #[derive(Clone, Copy)]
    struct FixedClock(u64);

    impl TrustedClock for FixedClock {
        fn now_ms(&self) -> Option<u64> {
            Some(self.0)
        }
    }

    fn digest(label: &str) -> Digest32 {
        Digest32::from_payload(label.as_bytes())
    }

    fn fixture() -> Result<
        (
            TaskCommitment,
            EffectProposal,
            AuthorizationDecision,
            ExecutionGrant,
            EffectReceipt,
        ),
        ProtocolError,
    > {
        let commitment = TaskCommitment {
            version: 1,
            commitment_id: "task-1".into(),
            principal: "user:alice".into(),
            objective_digest: digest("objective"),
            constraints_digest: digest("constraints"),
            authority_scope_digest: digest("authority"),
            policy_epoch: 7,
            configuration_epoch: 3,
            created_at_ms: 1_000,
            expires_at_ms: 20_000,
        };
        let proposal = EffectProposal {
            version: 1,
            proposal_id: "proposal-1".into(),
            commitment_hash: commitment.commitment()?,
            effect_profile: "mcp/tool-call@1".into(),
            operation: "filesystem.write".into(),
            target: "workspace:/report.md".into(),
            arguments_digest: digest("arguments"),
            expected_effect_digest: digest("expected effect"),
            pre_state_digest: digest("pre-state"),
            resource_claim_digest: digest("resources"),
            created_at_ms: 2_000,
            expires_at_ms: 15_000,
        };
        let decision = AuthorizationDecision {
            version: 1,
            decision_id: "decision-1".into(),
            proposal_hash: proposal.commitment()?,
            evidence_hashes: vec![digest("evidence")],
            outcome: DecisionOutcome::Allow,
            reason_codes: vec!["policy_allow".into()],
            decided_at_ms: 3_000,
            expires_at_ms: 10_000,
        };
        let grant = ExecutionGrant {
            version: 1,
            grant_id: "grant-1".into(),
            proposal_hash: proposal.commitment()?,
            decision_hash: decision.commitment()?,
            audience: "executor:local".into(),
            not_before_ms: 3_000,
            expires_at_ms: 9_000,
            uses: 1,
            nonce: "bm9uY2UtZm9yLWdyYW50LTE".into(),
        };
        let receipt = EffectReceipt {
            version: 1,
            receipt_id: "receipt-1".into(),
            proposal_hash: proposal.commitment()?,
            grant_hash: grant.commitment()?,
            attempt_id: "attempt-1".into(),
            claimed_at_ms: 4_000,
            dispatched_at_ms: Some(4_100),
            completed_at_ms: 4_200,
            outcome: ReceiptOutcome::Unknown,
            observation_digest: digest("timeout after dispatch"),
        };
        Ok((commitment, proposal, decision, grant, receipt))
    }

    fn claim_request(
        commitment: &TaskCommitment,
        proposal: &EffectProposal,
        attempt_id: impl Into<String>,
    ) -> GrantClaimRequest {
        GrantClaimRequest {
            attempt_id: attempt_id.into(),
            expected_audience: "executor:local".into(),
            observed_policy_epoch: commitment.policy_epoch,
            observed_configuration_epoch: commitment.configuration_epoch,
            observed_pre_state_digest: proposal.pre_state_digest.clone(),
            observed_resource_claim_digest: proposal.resource_claim_digest.clone(),
            revoked: false,
        }
    }

    #[test]
    fn verifies_complete_chain_and_reconciliation() -> Result<(), ProtocolError> {
        let (commitment, proposal, decision, grant, receipt) = fixture()?;
        let chain = verify_chain(&commitment, &proposal, &decision, &grant, &receipt)?;
        let reconciliation = ReconciliationRecord {
            version: 1,
            reconciliation_id: "reconciliation-1".into(),
            receipt_hash: chain.receipt_hash,
            sequence: 1,
            parent_reconciliation_hash: None,
            observed_at_ms: 5_000,
            outcome: ReconciliationOutcome::EffectConfirmed,
            evidence_digest: digest("authoritative observation"),
        };
        let _ = verify_reconciliation(&receipt, None, &reconciliation)?;
        Ok(())
    }

    #[test]
    fn verifies_every_portable_lifecycle_prefix() -> Result<(), ProtocolError> {
        let (commitment, proposal, decision, grant, receipt) = fixture()?;
        let mut bundle = TransactionBundle {
            commitment,
            proposal,
            decision,
            grant: None,
            receipt: None,
            reconciliations: Vec::new(),
        };
        assert_eq!(
            verify_transaction(&bundle)?.state,
            TransactionState::Decided
        );

        bundle.grant = Some(grant);
        assert_eq!(
            verify_transaction(&bundle)?.state,
            TransactionState::Granted
        );

        bundle.receipt = Some(receipt.clone());
        assert_eq!(
            verify_transaction(&bundle)?.state,
            TransactionState::Unknown
        );

        bundle.reconciliations.push(ReconciliationRecord {
            version: 1,
            reconciliation_id: "reconciliation-1".into(),
            receipt_hash: receipt.commitment()?,
            sequence: 1,
            parent_reconciliation_hash: None,
            observed_at_ms: 5_000,
            outcome: ReconciliationOutcome::EffectConfirmed,
            evidence_digest: digest("target audit event"),
        });
        let verified = verify_transaction(&bundle)?;
        assert_eq!(verified.state, TransactionState::EffectConfirmed);
        assert_eq!(verified.reconciliation_hashes.len(), 1);
        Ok(())
    }

    #[test]
    fn portable_bundle_rejects_missing_predecessors_and_duplicate_json_fields()
    -> Result<(), ProtocolError> {
        let (commitment, proposal, decision, _grant, receipt) = fixture()?;
        let invalid = TransactionBundle {
            commitment,
            proposal,
            decision,
            grant: None,
            receipt: Some(receipt),
            reconciliations: Vec::new(),
        };
        assert!(matches!(
            verify_transaction(&invalid),
            Err(ProtocolError::MissingPredecessor("grant"))
        ));

        let duplicate = br#"{"commitment":{},"commitment":{},"proposal":{},"decision":{},"grant":null,"receipt":null,"reconciliations":[]}"#;
        assert!(matches!(
            parse_transaction_bundle(duplicate),
            Err(ProtocolError::Json(_))
        ));
        Ok(())
    }

    #[test]
    fn substituted_proposal_is_rejected() -> Result<(), ProtocolError> {
        let (commitment, mut proposal, decision, grant, receipt) = fixture()?;
        proposal.target = "workspace:/different.md".into();
        let result = verify_chain(&commitment, &proposal, &decision, &grant, &receipt);
        assert!(matches!(result, Err(ProtocolError::ChainMismatch(_))));
        Ok(())
    }

    #[test]
    fn only_one_concurrent_claim_succeeds() -> Result<(), ProtocolError> {
        let (commitment, proposal, decision, grant, _) = fixture()?;
        let store = Arc::new(MemoryGrantStore::default());
        let _ = store.register(&commitment, &proposal, &decision, &grant)?;
        let mut workers = Vec::new();
        for index in 0..12 {
            let store = Arc::clone(&store);
            let grant = grant.clone();
            let request = claim_request(&commitment, &proposal, format!("attempt-{index}"));
            workers.push(thread::spawn(move || {
                store.claim(&grant, &request, &FixedClock(4_000)).is_ok()
            }));
        }
        let mut successes = 0;
        for worker in workers {
            if worker.join().unwrap_or(false) {
                successes += 1;
            }
        }
        assert_eq!(successes, 1);
        Ok(())
    }

    #[test]
    fn one_decision_can_issue_only_one_grant() -> Result<(), ProtocolError> {
        let (commitment, proposal, decision, grant, _) = fixture()?;
        let store = MemoryGrantStore::default();
        let _ = store.register(&commitment, &proposal, &decision, &grant)?;

        let mut second = grant.clone();
        second.grant_id = "grant-2".into();
        second.nonce = "c2Vjb25kLWdyYW50LW5vbmNlLTI".into();
        assert!(matches!(
            store.register(&commitment, &proposal, &decision, &second),
            Err(ProtocolError::DecisionAlreadyGranted)
        ));
        Ok(())
    }

    #[test]
    fn one_proposal_cannot_be_reauthorized_into_another_grant() -> Result<(), ProtocolError> {
        let (commitment, proposal, decision, grant, _) = fixture()?;
        let store = MemoryGrantStore::default();
        let _ = store.register(&commitment, &proposal, &decision, &grant)?;

        let mut second_decision = decision.clone();
        second_decision.decision_id = "decision-2".into();
        second_decision.reason_codes = vec!["policy_allow_after_retry".into()];
        let mut second_grant = grant.clone();
        second_grant.grant_id = "grant-2".into();
        second_grant.decision_hash = second_decision.commitment()?;
        second_grant.nonce = "c2Vjb25kLWdyYW50LW5vbmNlLTI".into();

        assert!(matches!(
            store.register(&commitment, &proposal, &second_decision, &second_grant),
            Err(ProtocolError::ProposalAlreadyGranted)
        ));
        Ok(())
    }

    #[test]
    fn claim_rechecks_currentness_and_records_attempt() -> Result<(), ProtocolError> {
        let (commitment, proposal, decision, grant, _) = fixture()?;
        let store = MemoryGrantStore::default();
        let _ = store.register(&commitment, &proposal, &decision, &grant)?;

        let mut request = claim_request(&commitment, &proposal, "attempt-current");
        request.observed_configuration_epoch += 1;
        assert!(matches!(
            store.claim(&grant, &request, &FixedClock(4_000)),
            Err(ProtocolError::StaleAuthority)
        ));

        request = claim_request(&commitment, &proposal, "attempt-current");
        request.revoked = true;
        assert!(matches!(
            store.claim(&grant, &request, &FixedClock(4_000)),
            Err(ProtocolError::GrantRevoked)
        ));

        request = claim_request(&commitment, &proposal, "attempt-current");
        assert!(matches!(
            store.claim(&grant, &request, &FixedClock(3_999)),
            Err(ProtocolError::ClockRollback)
        ));
        let claim = store.claim(&grant, &request, &FixedClock(4_000))?;
        assert_eq!(claim.attempt_id, "attempt-current");
        assert_eq!(claim.claimed_at_ms, 4_000);
        Ok(())
    }

    #[test]
    fn canonical_receipt_and_reconciliation_history_is_fork_free() -> Result<(), ProtocolError> {
        let (commitment, proposal, decision, grant, receipt) = fixture()?;
        let store = MemoryGrantStore::default();
        let _ = store.register(&commitment, &proposal, &decision, &grant)?;
        let request = claim_request(&commitment, &proposal, "attempt-1");
        let _ = store.claim(&grant, &request, &FixedClock(4_000))?;

        let receipt_hash = store.record_receipt(&receipt)?;
        assert_eq!(store.record_receipt(&receipt)?, receipt_hash);
        let mut conflicting_receipt = receipt.clone();
        conflicting_receipt.observation_digest = digest("conflicting observation");
        assert!(matches!(
            store.record_receipt(&conflicting_receipt),
            Err(ProtocolError::ReceiptAlreadyRecorded)
        ));

        let reconciliation = ReconciliationRecord {
            version: 1,
            reconciliation_id: "reconciliation-1".into(),
            receipt_hash,
            sequence: 1,
            parent_reconciliation_hash: None,
            observed_at_ms: 5_000,
            outcome: ReconciliationOutcome::StillUnknown,
            evidence_digest: digest("first observation"),
        };
        let reconciliation_hash = store.append_reconciliation(&reconciliation)?;
        assert_eq!(
            store.append_reconciliation(&reconciliation)?,
            reconciliation_hash
        );
        let mut fork = reconciliation;
        fork.reconciliation_id = "reconciliation-fork".into();
        fork.evidence_digest = digest("contradictory branch");
        assert!(matches!(
            store.append_reconciliation(&fork),
            Err(ProtocolError::ReconciliationFork)
        ));
        Ok(())
    }

    #[test]
    fn store_rejects_proposal_outside_committed_window() -> Result<(), ProtocolError> {
        let (commitment, mut proposal, mut decision, mut grant, _) = fixture()?;
        proposal.expires_at_ms = commitment.expires_at_ms + 1;
        decision.proposal_hash = proposal.commitment()?;
        grant.proposal_hash = decision.proposal_hash.clone();
        grant.decision_hash = decision.commitment()?;

        let store = MemoryGrantStore::default();
        assert!(matches!(
            store.register(&commitment, &proposal, &decision, &grant),
            Err(ProtocolError::InvalidNestedWindow("proposal"))
        ));
        Ok(())
    }

    #[test]
    fn store_rejects_decision_outside_proposal_window() -> Result<(), ProtocolError> {
        let (commitment, proposal, mut decision, mut grant, _) = fixture()?;
        decision.expires_at_ms = proposal.expires_at_ms + 1;
        grant.decision_hash = decision.commitment()?;

        let store = MemoryGrantStore::default();
        assert!(matches!(
            store.register(&commitment, &proposal, &decision, &grant),
            Err(ProtocolError::InvalidNestedWindow("decision"))
        ));
        Ok(())
    }

    #[test]
    fn canonical_json_is_key_order_independent() -> Result<(), ProtocolError> {
        let first: Value =
            serde_json::from_str(r#"{"z":1,"a":{"b":2,"a":1}}"#).map_err(ProtocolError::Json)?;
        let second: Value =
            serde_json::from_str(r#"{"a":{"a":1,"b":2},"z":1}"#).map_err(ProtocolError::Json)?;
        assert_eq!(canonical_json(&first)?, canonical_json(&second)?);
        Ok(())
    }

    #[test]
    fn floats_and_unsafe_integers_are_rejected() {
        let float = serde_json::json!({"value": 1.5});
        let unsafe_integer = serde_json::json!({"value": MAX_SAFE_INTEGER + 1});
        assert!(matches!(
            canonical_json(&float),
            Err(ProtocolError::UnsafeJsonNumber)
        ));
        assert!(matches!(
            canonical_json(&unsafe_integer),
            Err(ProtocolError::UnsafeJsonNumber)
        ));
    }

    #[test]
    fn enforces_core_field_and_lifetime_limits() -> Result<(), ProtocolError> {
        let (_, mut proposal, mut decision, mut grant, _) = fixture()?;

        proposal.operation = "Filesystem.Write".into();
        assert!(matches!(
            proposal.validate(),
            Err(ProtocolError::InvalidToken("operation"))
        ));

        decision.reason_codes.clear();
        assert!(matches!(
            decision.validate(),
            Err(ProtocolError::MissingReasonCode)
        ));

        grant.expires_at_ms = grant.not_before_ms + MAX_GRANT_LIFETIME_MS + 1;
        assert!(matches!(
            grant.validate(),
            Err(ProtocolError::GrantLifetimeExceeded)
        ));
        Ok(())
    }

    #[test]
    fn field_limits_count_utf8_bytes_not_unicode_scalars() -> Result<(), ProtocolError> {
        let (mut commitment, _, _, _, _) = fixture()?;
        commitment.commitment_id = "é".repeat(256);
        assert_eq!(commitment.commitment_id.chars().count(), 256);
        assert_eq!(commitment.commitment_id.len(), 512);
        assert!(matches!(
            commitment.validate(),
            Err(ProtocolError::InvalidBinding("commitment_id"))
        ));
        Ok(())
    }

    #[test]
    fn malformed_digests_fail_during_deserialization() {
        for value in [
            r#""garbage""#,
            r#""sha256:0000000000000000000000000000000000000000000000000000000000000000""#,
        ] {
            assert!(serde_json::from_str::<Digest32>(value).is_err());
        }
    }

    #[test]
    fn strict_record_parser_rejects_duplicate_fields_and_oversized_input()
    -> Result<(), ProtocolError> {
        let (commitment, _, _, _, _) = fixture()?;
        let encoded = serde_json::to_string(&commitment).map_err(ProtocolError::Json)?;
        let duplicate = encoded.replacen(
            r#""commitment_id":"task-1""#,
            r#""commitment_id":"task-1","commitment_id":"task-2""#,
            1,
        );
        assert!(parse_record::<TaskCommitment>(duplicate.as_bytes()).is_err());

        let oversized = vec![b' '; MAX_TRANSPORT_INPUT_BYTES + 1];
        assert!(matches!(
            parse_record::<TaskCommitment>(&oversized),
            Err(ProtocolError::ResourceLimit("transport bytes"))
        ));
        Ok(())
    }

    #[test]
    fn canonicalizer_rejects_excessive_nesting() {
        let mut value = Value::Null;
        for _ in 0..MAX_CANONICAL_NESTING_DEPTH {
            value = Value::Array(vec![value]);
        }
        assert!(matches!(
            canonical_json(&value),
            Err(ProtocolError::ResourceLimit("JSON nesting depth"))
        ));
    }

    #[test]
    fn receipt_distinguishes_not_dispatched_from_unknown() -> Result<(), ProtocolError> {
        let (_, _, _, _, mut receipt) = fixture()?;
        receipt.outcome = ReceiptOutcome::NotDispatched;
        receipt.dispatched_at_ms = None;
        receipt.validate()?;

        receipt.outcome = ReceiptOutcome::Succeeded;
        assert!(matches!(
            receipt.validate(),
            Err(ProtocolError::MissingDispatchEvidence)
        ));

        receipt.outcome = ReceiptOutcome::Unknown;
        receipt.validate()?;
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            failure_persistence: None,
            rng_seed: RngSeed::Fixed(0x4554_502D_4A53_4F4E),
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_bounded_json_bytes_never_panic_or_skip_validation(
            input in proptest::collection::vec(any::<u8>(), 0..=65_536)
        ) {
            if let Ok(record) = parse_record::<TaskCommitment>(&input) {
                prop_assert!(record.validate().is_ok());
                prop_assert!(canonical_json(&record).is_ok());
            }
            if let Ok(bundle) = parse_transaction_bundle(&input) {
                prop_assert!(verify_transaction(&bundle).is_ok());
            }
        }

        #[test]
        fn bytes_over_transport_limit_are_rejected_before_parsing(
            mut prefix in proptest::collection::vec(any::<u8>(), 0..=4_096),
            fill in any::<u8>(),
            excess in 1usize..=4_096,
        ) {
            prefix.resize(MAX_TRANSPORT_INPUT_BYTES + excess, fill);
            prop_assert!(matches!(
                parse_record::<TaskCommitment>(&prefix),
                Err(ProtocolError::ResourceLimit("transport bytes"))
            ));
            prop_assert!(matches!(
                parse_transaction_bundle(&prefix),
                Err(ProtocolError::ResourceLimit("transport bytes"))
            ));
        }
    }
}

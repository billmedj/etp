//! Authorization and dispatch boundary for one ETP effect.
//!
//! The type-state API orders verification, durable claim, dispatch marking,
//! receipt recording, and reconciliation. Effect-profile validation occurs
//! before this boundary. This crate binds the exact document bytes supplied by
//! the caller; it does not parse an HTTP, Kubernetes, or other effect profile.
//! The crate does not provide a target adapter.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;

use effect_transaction_authority::{
    AuthorityError, AuthoritySnapshot, RecordKind, VerificationContext, VerifiedAuthority,
    verify_authority,
};
use effect_transaction_core::{
    AuthorizationDecision, Digest32, EffectProposal, EffectReceipt, ExecutionGrant,
    MAX_TRANSPORT_INPUT_BYTES, ProtocolError, ProtocolRecord, ReceiptOutcome, ReconciliationRecord,
    TaskCommitment, verify_grant,
};
use effect_transaction_sqlite::{
    ClaimRequest, CurrentnessSnapshot, DurableClaim, Lifecycle, SqliteEffectStore, StoreError,
};
use thiserror::Error;

/// ETP core profile signed by the authority assertion.
pub const CORE_RECORD_PROFILE: &str = "effect-transaction/core/0.1";
/// Maximum accepted age for a trusted target-currentness snapshot.
pub const MAX_CURRENTNESS_AGE_MS: u64 = effect_transaction_sqlite::MAX_CURRENTNESS_AGE_MS;

/// Local executor policy.
///
/// The audience and authority role are literal values, not patterns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorPolicy {
    pub audience: String,
    pub authority_role: String,
    pub maximum_authority_snapshot_age_ms: u64,
    pub maximum_currentness_age_ms: u64,
}

impl ExecutorPolicy {
    /// Validates the executor policy.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::InvalidPolicy`] for an empty, padded, invalid,
    /// or overly broad value.
    pub fn validate(&self) -> Result<(), ExecutorError> {
        validate_text(&self.audience, 512)?;
        validate_token(&self.authority_role)?;
        if self.maximum_authority_snapshot_age_ms == 0
            || self.maximum_authority_snapshot_age_ms
                > effect_transaction_authority::MAX_AUTHORITY_SNAPSHOT_AGE_MS
        {
            return Err(ExecutorError::InvalidPolicy(
                "authority snapshot age must be within the authority profile bound",
            ));
        }
        if self.maximum_currentness_age_ms == 0
            || self.maximum_currentness_age_ms > MAX_CURRENTNESS_AGE_MS
        {
            return Err(ExecutorError::InvalidPolicy(
                "currentness age must be within the executor profile bound",
            ));
        }
        Ok(())
    }
}

/// The exact bytes of the four profile documents committed by a proposal.
///
/// A profile-aware caller must validate and encode these documents before it
/// constructs this value. This type treats the bytes as opaque.
///
/// The API does not release these bytes before it writes the dispatch marker.
pub struct EffectDocuments {
    arguments: Vec<u8>,
    expected_effect: Vec<u8>,
    pre_state: Vec<u8>,
    resource_claim: Vec<u8>,
}

impl fmt::Debug for EffectDocuments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectDocuments")
            .field("arguments_bytes", &self.arguments.len())
            .field("expected_effect_bytes", &self.expected_effect.len())
            .field("pre_state_bytes", &self.pre_state.len())
            .field("resource_claim_bytes", &self.resource_claim.len())
            .finish()
    }
}

impl EffectDocuments {
    /// Stores caller-validated profile-document bytes without parsing them.
    ///
    /// [`PreparedEffect::new`] checks the byte limits and digest bindings. It
    /// does not check profile schemas or profile-specific semantic rules.
    #[must_use]
    pub fn new(
        arguments: Vec<u8>,
        expected_effect: Vec<u8>,
        pre_state: Vec<u8>,
        resource_claim: Vec<u8>,
    ) -> Self {
        Self {
            arguments,
            expected_effect,
            pre_state,
            resource_claim,
        }
    }

    fn validate_limits(&self) -> Result<(), ExecutorError> {
        for (name, value) in [
            ("arguments", &self.arguments),
            ("expected effect", &self.expected_effect),
            ("pre-state", &self.pre_state),
            ("resource claim", &self.resource_claim),
        ] {
            if value.len() > MAX_TRANSPORT_INPUT_BYTES {
                return Err(ExecutorError::DocumentTooLarge(name));
            }
        }
        Ok(())
    }
}

/// A verified authorization chain with byte-exact document bindings.
///
/// `authorize_and_claim` consumes this value. The value does not expose target
/// data.
pub struct PreparedEffect {
    commitment: TaskCommitment,
    proposal: EffectProposal,
    decision: AuthorizationDecision,
    grant: ExecutionGrant,
    documents: EffectDocuments,
    grant_hash: Digest32,
    proposal_hash: Digest32,
}

impl fmt::Debug for PreparedEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEffect")
            .field("commitment_id", &self.commitment.commitment_id)
            .field("proposal_id", &self.proposal.proposal_id)
            .field("decision_id", &self.decision.decision_id)
            .field("grant_id", &self.grant.grant_id)
            .field("proposal_hash", &self.proposal_hash)
            .field("grant_hash", &self.grant_hash)
            .field("documents", &self.documents)
            .finish()
    }
}

impl PreparedEffect {
    /// Verifies the task-to-grant chain and the exact profile-document bytes.
    ///
    /// The caller must first validate each document under the proposal's
    /// registered effect profile. This method enforces only the transport byte
    /// limit and the SHA-256 binding for those opaque bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid chain or an invalid profile-document size
    /// or digest.
    pub fn new(
        commitment: TaskCommitment,
        proposal: EffectProposal,
        decision: AuthorizationDecision,
        grant: ExecutionGrant,
        documents: EffectDocuments,
    ) -> Result<Self, ExecutorError> {
        documents.validate_limits()?;
        let grant_hash = verify_grant(&commitment, &proposal, &decision, &grant)?;
        let proposal_hash = proposal.commitment()?;
        verify_document(
            "arguments",
            &documents.arguments,
            &proposal.arguments_digest,
        )?;
        verify_document(
            "expected effect",
            &documents.expected_effect,
            &proposal.expected_effect_digest,
        )?;
        verify_document(
            "pre-state",
            &documents.pre_state,
            &proposal.pre_state_digest,
        )?;
        verify_document(
            "resource claim",
            &documents.resource_claim,
            &proposal.resource_claim_digest,
        )?;
        Ok(Self {
            commitment,
            proposal,
            decision,
            grant,
            documents,
            grant_hash,
            proposal_hash,
        })
    }
}

/// Audit data for the authority check that preceded the winning claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityEvidence {
    pub statement_id: String,
    pub issuer: String,
    pub key_id: String,
    pub role: String,
    pub audience: String,
    pub verified_at_ms: u64,
    pub snapshot_observed_at_ms: u64,
    pub verifying_key_digest: Digest32,
}

impl From<VerifiedAuthority> for AuthorityEvidence {
    fn from(value: VerifiedAuthority) -> Self {
        let statement = value.statement();
        Self {
            statement_id: statement.statement_id.clone(),
            issuer: statement.issuer.clone(),
            key_id: statement.key_id.clone(),
            role: statement.role.clone(),
            audience: statement.audience.clone(),
            verified_at_ms: value.verified_at_ms(),
            snapshot_observed_at_ms: value.snapshot_observed_at_ms(),
            verifying_key_digest: value.verifying_key_digest().clone(),
        }
    }
}

/// Opaque winning claim that does not expose target data.
pub struct ClaimedEffect {
    prepared: PreparedEffect,
    claim: DurableClaim,
    authority: AuthorityEvidence,
    signed_authority: Vec<u8>,
}

impl fmt::Debug for ClaimedEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedEffect")
            .field("grant_hash", &self.claim.grant_hash)
            .field("attempt_id", &self.claim.attempt_id)
            .field("claimed_at_ms", &self.claim.claimed_at_ms)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl ClaimedEffect {
    #[must_use]
    pub fn grant_hash(&self) -> &Digest32 {
        &self.claim.grant_hash
    }

    #[must_use]
    pub fn proposal_hash(&self) -> &Digest32 {
        &self.prepared.proposal_hash
    }

    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.claim.attempt_id
    }

    #[must_use]
    pub const fn claimed_at_ms(&self) -> u64 {
        self.claim.claimed_at_ms
    }

    #[must_use]
    pub const fn authority_evidence(&self) -> &AuthorityEvidence {
        &self.authority
    }
}

/// Single-use capability issued after a currentness check and durable dispatch
/// marker.
pub struct DispatchCapability {
    prepared: PreparedEffect,
    claim: DurableClaim,
    dispatched_at_ms: u64,
}

impl fmt::Debug for DispatchCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchCapability")
            .field("grant_hash", &self.claim.grant_hash)
            .field("attempt_id", &self.claim.attempt_id)
            .field("dispatched_at_ms", &self.dispatched_at_ms)
            .finish_non_exhaustive()
    }
}

/// Owned effect data passed once to a caller-supplied target adapter.
pub struct ExactEffect {
    effect_profile: String,
    operation: String,
    target: String,
    documents: EffectDocuments,
}

impl fmt::Debug for ExactEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactEffect")
            .field("effect_profile", &self.effect_profile)
            .field("operation", &self.operation)
            .field("target_bytes", &self.target.len())
            .field("documents", &self.documents)
            .finish()
    }
}

impl ExactEffect {
    #[must_use]
    pub fn effect_profile(&self) -> &str {
        &self.effect_profile
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub fn arguments(&self) -> &[u8] {
        &self.documents.arguments
    }

    #[must_use]
    pub fn expected_effect(&self) -> &[u8] {
        &self.documents.expected_effect
    }

    #[must_use]
    pub fn pre_state(&self) -> &[u8] {
        &self.documents.pre_state
    }

    #[must_use]
    pub fn resource_claim(&self) -> &[u8] {
        &self.documents.resource_claim
    }
}

/// Attempt data retained after the effect is passed to an adapter.
pub struct ReceiptHandle {
    proposal_hash: Digest32,
    grant_hash: Digest32,
    attempt_id: String,
    claimed_at_ms: u64,
    dispatched_at_ms: u64,
}

impl fmt::Debug for ReceiptHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptHandle")
            .field("proposal_hash", &self.proposal_hash)
            .field("grant_hash", &self.grant_hash)
            .field("attempt_id", &self.attempt_id)
            .field("claimed_at_ms", &self.claimed_at_ms)
            .field("dispatched_at_ms", &self.dispatched_at_ms)
            .finish()
    }
}

impl DispatchCapability {
    /// Consumes the capability and passes the effect to one adapter invocation.
    ///
    /// If the adapter panics or the process stops, the dispatch marker remains.
    /// Recovery must record an `unknown` outcome.
    pub fn dispatch_with<R>(self, adapter: impl FnOnce(ExactEffect) -> R) -> (ReceiptHandle, R) {
        let Self {
            prepared,
            claim,
            dispatched_at_ms,
        } = self;
        let exact = ExactEffect {
            effect_profile: prepared.proposal.effect_profile,
            operation: prepared.proposal.operation,
            target: prepared.proposal.target,
            documents: prepared.documents,
        };
        let handle = ReceiptHandle {
            proposal_hash: prepared.proposal_hash,
            grant_hash: claim.grant_hash,
            attempt_id: claim.attempt_id,
            claimed_at_ms: claim.claimed_at_ms,
            dispatched_at_ms,
        };
        let result = adapter(exact);
        (handle, result)
    }
}

/// Outcome after dispatch starts.
///
/// This type cannot represent `not_dispatched`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchedOutcome {
    Succeeded,
    Failed,
    Unknown,
}

impl From<DispatchedOutcome> for ReceiptOutcome {
    fn from(value: DispatchedOutcome) -> Self {
        match value {
            DispatchedOutcome::Succeeded => Self::Succeeded,
            DispatchedOutcome::Failed => Self::Failed,
            DispatchedOutcome::Unknown => Self::Unknown,
        }
    }
}

/// Caller-supplied evidence for a pre-dispatch close.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotDispatchedReceipt {
    pub receipt_id: String,
    pub completed_at_ms: u64,
    pub observation_digest: Digest32,
}

/// Caller-supplied evidence collected after dispatch starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchedReceipt {
    pub receipt_id: String,
    pub completed_at_ms: u64,
    pub outcome: DispatchedOutcome,
    pub observation_digest: Digest32,
}

/// Persisted identifiers needed to recover a crash after the dispatch marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownRecovery {
    pub receipt_id: String,
    pub proposal_hash: Digest32,
    pub grant_hash: Digest32,
    pub attempt_id: String,
    pub completed_at_ms: u64,
    pub observation_digest: Digest32,
}

/// Persisted identifiers needed to recover a crash before the dispatch marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotDispatchedRecovery {
    pub receipt_id: String,
    pub proposal_hash: Digest32,
    pub grant_hash: Digest32,
    pub attempt_id: String,
    pub completed_at_ms: u64,
    pub observation_digest: Digest32,
}

/// Durable reference ETP executor.
pub struct EffectTransactionExecutor {
    policy: ExecutorPolicy,
    store: SqliteEffectStore,
}

impl fmt::Debug for EffectTransactionExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectTransactionExecutor")
            .field("policy", &self.policy)
            .field("store", &self.store)
            .finish()
    }
}

impl EffectTransactionExecutor {
    /// Opens the durable store and validates the local executor policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid policy or unavailable `SQLite` store.
    pub fn open(path: impl AsRef<Path>, policy: ExecutorPolicy) -> Result<Self, ExecutorError> {
        policy.validate()?;
        Ok(Self {
            policy,
            store: SqliteEffectStore::open(path)?,
        })
    }

    #[must_use]
    pub const fn policy(&self) -> &ExecutorPolicy {
        &self.policy
    }

    /// Advances target currentness from a trusted host observation.
    ///
    /// A newer record can make a pending claim or dispatch stale. The store
    /// enforces monotonic versions, epochs, observation time, and revocation.
    ///
    /// # Errors
    ///
    /// Returns an error for stale input, a monotonicity or revocation conflict,
    /// or unavailable storage.
    pub fn observe_currentness(
        &mut self,
        currentness: &CurrentnessSnapshot,
        trusted_now_ms: u64,
    ) -> Result<(), ExecutorError> {
        self.check_currentness_freshness(currentness, trusted_now_ms)?;
        self.store
            .put_currentness(currentness)
            .map_err(ExecutorError::from)
    }

    /// Verifies authority and atomically claims the grant under currentness.
    ///
    /// The host must obtain `authority_snapshot`, `currentness`, and
    /// `trusted_now_ms` from authenticated sources. This API does not
    /// authenticate these inputs.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid chain, document, authority, time, epoch,
    /// audience, currentness, replay state, or durable-store state.
    pub fn authorize_and_claim(
        &mut self,
        prepared: PreparedEffect,
        signed_authority: &[u8],
        authority_snapshot: &AuthoritySnapshot,
        currentness: &CurrentnessSnapshot,
        attempt_id: impl Into<String>,
        trusted_now_ms: u64,
    ) -> Result<ClaimedEffect, ExecutorError> {
        self.check_currentness_freshness(currentness, trusted_now_ms)?;
        if prepared.grant.audience != self.policy.audience {
            return Err(ExecutorError::GrantAudienceMismatch);
        }
        if authority_snapshot.configuration_epoch != prepared.commitment.configuration_epoch {
            return Err(ExecutorError::AuthorityConfigurationEpochMismatch);
        }
        if currentness.policy_epoch != prepared.commitment.policy_epoch {
            return Err(ExecutorError::CurrentnessPolicyEpochMismatch);
        }
        if currentness.configuration_epoch != prepared.commitment.configuration_epoch {
            return Err(ExecutorError::CurrentnessConfigurationEpochMismatch);
        }

        let verified = verify_authority(
            signed_authority,
            authority_snapshot,
            VerificationContext {
                expected_record_profile: CORE_RECORD_PROFILE,
                expected_record_version: prepared.grant.version,
                expected_record_kind: RecordKind::ExecutionGrant,
                expected_record_digest: &prepared.grant_hash,
                expected_role: &self.policy.authority_role,
                expected_audience: &self.policy.audience,
                now_ms: trusted_now_ms,
                maximum_snapshot_age_ms: self.policy.maximum_authority_snapshot_age_ms,
            },
        )?;

        self.store.register_chain(
            &prepared.commitment,
            &prepared.proposal,
            &prepared.decision,
            &prepared.grant,
        )?;
        self.store.put_currentness(currentness)?;
        let claim = self.store.claim(
            &prepared.grant,
            &ClaimRequest {
                attempt_id: attempt_id.into(),
                expected_audience: self.policy.audience.clone(),
                currentness_key: currentness.key.clone(),
                expected_snapshot_version: currentness.version,
                maximum_snapshot_age_ms: self.policy.maximum_currentness_age_ms,
            },
            trusted_now_ms,
        )?;
        Ok(ClaimedEffect {
            prepared,
            claim,
            authority: verified.into(),
            signed_authority: signed_authority.to_vec(),
        })
    }

    /// Verifies current authority and currentness again, then writes the dispatch
    /// marker before it returns a capability.
    ///
    /// # Errors
    ///
    /// Returns an error for expiry, rollback, changed state, revocation,
    /// mismatched input, or a conflicting dispatch marker.
    pub fn begin_dispatch(
        &mut self,
        claimed: ClaimedEffect,
        authority_snapshot: &AuthoritySnapshot,
        trusted_now_ms: u64,
    ) -> Result<DispatchCapability, ExecutorError> {
        if authority_snapshot.configuration_epoch != claimed.prepared.commitment.configuration_epoch
        {
            return Err(ExecutorError::AuthorityConfigurationEpochMismatch);
        }
        let reverified = AuthorityEvidence::from(verify_authority(
            &claimed.signed_authority,
            authority_snapshot,
            VerificationContext {
                expected_record_profile: CORE_RECORD_PROFILE,
                expected_record_version: claimed.prepared.grant.version,
                expected_record_kind: RecordKind::ExecutionGrant,
                expected_record_digest: &claimed.prepared.grant_hash,
                expected_role: &self.policy.authority_role,
                expected_audience: &self.policy.audience,
                now_ms: trusted_now_ms,
                maximum_snapshot_age_ms: self.policy.maximum_authority_snapshot_age_ms,
            },
        )?);
        if !same_authority_identity(&claimed.authority, &reverified) {
            return Err(ExecutorError::AuthorityChangedAfterClaim);
        }
        let marker = self.store.mark_dispatch_started(
            &claimed.claim.grant_hash,
            &claimed.claim.attempt_id,
            trusted_now_ms,
        )?;
        Ok(DispatchCapability {
            prepared: claimed.prepared,
            claim: claimed.claim,
            dispatched_at_ms: marker.dispatched_at_ms,
        })
    }

    /// Closes a winning claim before dispatch starts.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt timeline or stored lifecycle conflicts
    /// with a `not_dispatched` outcome.
    pub fn record_not_dispatched(
        &mut self,
        claimed: ClaimedEffect,
        evidence: NotDispatchedReceipt,
    ) -> Result<Digest32, ExecutorError> {
        self.store
            .record_receipt(&EffectReceipt {
                version: 1,
                receipt_id: evidence.receipt_id,
                proposal_hash: claimed.prepared.proposal_hash,
                grant_hash: claimed.claim.grant_hash,
                attempt_id: claimed.claim.attempt_id,
                claimed_at_ms: claimed.claim.claimed_at_ms,
                dispatched_at_ms: None,
                completed_at_ms: evidence.completed_at_ms,
                outcome: ReceiptOutcome::NotDispatched,
                observation_digest: evidence.observation_digest,
            })
            .map_err(ExecutorError::from)
    }

    /// Records the observed outcome for one marked dispatch attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid timeline, attempt mismatch, marker
    /// mismatch, or conflicting receipt.
    pub fn record_dispatched(
        &mut self,
        handle: ReceiptHandle,
        evidence: DispatchedReceipt,
    ) -> Result<Digest32, ExecutorError> {
        self.store
            .record_receipt(&EffectReceipt {
                version: 1,
                receipt_id: evidence.receipt_id,
                proposal_hash: handle.proposal_hash,
                grant_hash: handle.grant_hash,
                attempt_id: handle.attempt_id,
                claimed_at_ms: handle.claimed_at_ms,
                dispatched_at_ms: Some(handle.dispatched_at_ms),
                completed_at_ms: evidence.completed_at_ms,
                outcome: evidence.outcome.into(),
                observation_digest: evidence.observation_digest,
            })
            .map_err(ExecutorError::from)
    }

    /// Records an `unknown` receipt after a crash with a dispatch marker.
    ///
    /// The stored lifecycle supplies the claim and marker timestamps. The caller
    /// cannot change them through this API.
    ///
    /// # Errors
    ///
    /// Returns an error unless the grant has a matching claim and dispatch
    /// marker, no conflicting receipt, and the required proposal binding.
    pub fn record_recovered_unknown(
        &mut self,
        recovery: UnknownRecovery,
    ) -> Result<Digest32, ExecutorError> {
        let lifecycle = self.store.lifecycle(&recovery.grant_hash)?;
        let claim = lifecycle.claim.ok_or(ExecutorError::MissingDurableClaim)?;
        if claim.attempt_id != recovery.attempt_id {
            return Err(ExecutorError::RecoveryAttemptMismatch);
        }
        let dispatched_at_ms = claim
            .dispatch_started_at_ms
            .ok_or(ExecutorError::MissingDispatchMarker)?;
        self.store
            .record_receipt(&EffectReceipt {
                version: 1,
                receipt_id: recovery.receipt_id,
                proposal_hash: recovery.proposal_hash,
                grant_hash: recovery.grant_hash,
                attempt_id: recovery.attempt_id,
                claimed_at_ms: claim.claimed_at_ms,
                dispatched_at_ms: Some(dispatched_at_ms),
                completed_at_ms: recovery.completed_at_ms,
                outcome: ReceiptOutcome::Unknown,
                observation_digest: recovery.observation_digest,
            })
            .map_err(ExecutorError::from)
    }

    /// Records `not_dispatched` after a crash with no dispatch marker.
    ///
    /// The stored lifecycle supplies the claim timestamp and confirms that no
    /// dispatch marker exists. This method cannot run after dispatch starts.
    ///
    /// # Errors
    ///
    /// Returns an error unless the grant has a matching claim, no dispatch
    /// marker, no conflicting receipt, and the required proposal binding.
    pub fn record_recovered_not_dispatched(
        &mut self,
        recovery: NotDispatchedRecovery,
    ) -> Result<Digest32, ExecutorError> {
        let lifecycle = self.store.lifecycle(&recovery.grant_hash)?;
        let claim = lifecycle.claim.ok_or(ExecutorError::MissingDurableClaim)?;
        if claim.attempt_id != recovery.attempt_id {
            return Err(ExecutorError::RecoveryAttemptMismatch);
        }
        if claim.dispatch_started_at_ms.is_some() {
            return Err(ExecutorError::UnexpectedDispatchMarker);
        }
        self.store
            .record_receipt(&EffectReceipt {
                version: 1,
                receipt_id: recovery.receipt_id,
                proposal_hash: recovery.proposal_hash,
                grant_hash: recovery.grant_hash,
                attempt_id: recovery.attempt_id,
                claimed_at_ms: claim.claimed_at_ms,
                dispatched_at_ms: None,
                completed_at_ms: recovery.completed_at_ms,
                outcome: ReceiptOutcome::NotDispatched,
                observation_digest: recovery.observation_digest,
            })
            .map_err(ExecutorError::from)
    }

    /// Appends one reconciliation record for an `unknown` receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-unknown receipt, invalid parent, fork,
    /// terminal extension, duplicate identifier, or unavailable store.
    pub fn append_reconciliation(
        &mut self,
        record: &ReconciliationRecord,
    ) -> Result<Digest32, ExecutorError> {
        self.store
            .append_reconciliation(record)
            .map_err(ExecutorError::from)
    }

    /// Reads the durable lifecycle for audit or crash recovery.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid stored data or unavailable storage.
    pub fn lifecycle(&self, grant_hash: &Digest32) -> Result<Lifecycle, ExecutorError> {
        self.store
            .lifecycle(grant_hash)
            .map_err(ExecutorError::from)
    }

    fn check_currentness_freshness(
        &self,
        currentness: &CurrentnessSnapshot,
        now_ms: u64,
    ) -> Result<(), ExecutorError> {
        if currentness.observed_at_ms > now_ms {
            return Err(ExecutorError::CurrentnessFromFuture);
        }
        if now_ms - currentness.observed_at_ms > self.policy.maximum_currentness_age_ms {
            return Err(ExecutorError::StaleCurrentness);
        }
        Ok(())
    }
}

fn verify_document(
    name: &'static str,
    bytes: &[u8],
    expected: &Digest32,
) -> Result<(), ExecutorError> {
    if &Digest32::from_payload(bytes) == expected {
        Ok(())
    } else {
        Err(ExecutorError::DocumentDigestMismatch(name))
    }
}

fn validate_text(value: &str, maximum_bytes: usize) -> Result<(), ExecutorError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(ExecutorError::InvalidPolicy("invalid text value"))
    } else {
        Ok(())
    }
}

fn validate_token(value: &str) -> Result<(), ExecutorError> {
    validate_text(value, 256)?;
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(b'a'..=b'z'))
        || !bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'/' | b'-'
            )
        })
    {
        return Err(ExecutorError::InvalidPolicy("invalid authority role"));
    }
    Ok(())
}

fn same_authority_identity(first: &AuthorityEvidence, second: &AuthorityEvidence) -> bool {
    first.statement_id == second.statement_id
        && first.issuer == second.issuer
        && first.key_id == second.key_id
        && first.role == second.role
        && first.audience == second.audience
        && first.verifying_key_digest == second.verifying_key_digest
}

/// Errors returned by the executor.
#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("invalid executor policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("effect-profile document exceeds the transport bound: {0}")]
    DocumentTooLarge(&'static str),
    #[error("effect-profile document digest mismatch: {0}")]
    DocumentDigestMismatch(&'static str),
    #[error("grant audience does not match this executor")]
    GrantAudienceMismatch,
    #[error("authority snapshot epoch does not match the task configuration epoch")]
    AuthorityConfigurationEpochMismatch,
    #[error("authority identity changed after claim")]
    AuthorityChangedAfterClaim,
    #[error("currentness policy epoch does not match live authority")]
    CurrentnessPolicyEpochMismatch,
    #[error("currentness configuration epoch does not match live authority")]
    CurrentnessConfigurationEpochMismatch,
    #[error("currentness snapshot is from the future")]
    CurrentnessFromFuture,
    #[error("currentness snapshot is stale")]
    StaleCurrentness,
    #[error("recovery found no winning claim")]
    MissingDurableClaim,
    #[error("recovery attempt does not match the winning claim")]
    RecoveryAttemptMismatch,
    #[error("recovery found no dispatch marker")]
    MissingDispatchMarker,
    #[error("dispatch marker conflicts with not_dispatched recovery")]
    UnexpectedDispatchMarker,
    #[error("ETP record validation failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("authority verification failed: {0}")]
    Authority(#[from] AuthorityError),
    #[error("ETP state transition failed: {0}")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use effect_transaction_authority::{AUTHORITY_PROFILE, AuthorityStatement, SigningAuthority};
    use effect_transaction_core::{DecisionOutcome, PROFILE_VERSION, ReconciliationOutcome};

    use super::*;

    const NOW: u64 = 4_000;

    #[derive(Clone)]
    struct Fixture {
        commitment: TaskCommitment,
        proposal: EffectProposal,
        decision: AuthorizationDecision,
        grant: ExecutionGrant,
        arguments: Vec<u8>,
        expected_effect: Vec<u8>,
        pre_state: Vec<u8>,
        resource_claim: Vec<u8>,
    }

    impl Fixture {
        fn prepared(&self) -> Result<PreparedEffect, ExecutorError> {
            PreparedEffect::new(
                self.commitment.clone(),
                self.proposal.clone(),
                self.decision.clone(),
                self.grant.clone(),
                EffectDocuments::new(
                    self.arguments.clone(),
                    self.expected_effect.clone(),
                    self.pre_state.clone(),
                    self.resource_claim.clone(),
                ),
            )
        }
    }

    fn fixture(suffix: &str) -> Result<Fixture, ProtocolError> {
        let arguments = format!(r#"{{"content":"{suffix}","path":"/{suffix}.md"}}"#).into_bytes();
        let expected_effect = format!(r#"{{"sha256":"{suffix}"}}"#).into_bytes();
        let pre_state = br#"{"exists":false}"#.to_vec();
        let resource_claim = br#"{"writes":1}"#.to_vec();
        let commitment = TaskCommitment {
            version: PROFILE_VERSION,
            commitment_id: format!("task-{suffix}"),
            principal: "user:alice".into(),
            objective_digest: Digest32::from_payload(b"objective"),
            constraints_digest: Digest32::from_payload(b"constraints"),
            authority_scope_digest: Digest32::from_payload(b"authority scope"),
            policy_epoch: 7,
            configuration_epoch: 3,
            created_at_ms: 1_000,
            expires_at_ms: 20_000,
        };
        let proposal = EffectProposal {
            version: PROFILE_VERSION,
            proposal_id: format!("proposal-{suffix}"),
            commitment_hash: commitment.commitment()?,
            effect_profile: "filesystem/canonical-write@1".into(),
            operation: "filesystem.write".into(),
            target: format!("workspace:/{suffix}.md"),
            arguments_digest: Digest32::from_payload(&arguments),
            expected_effect_digest: Digest32::from_payload(&expected_effect),
            pre_state_digest: Digest32::from_payload(&pre_state),
            resource_claim_digest: Digest32::from_payload(&resource_claim),
            created_at_ms: 2_000,
            expires_at_ms: 15_000,
        };
        let decision = AuthorizationDecision {
            version: PROFILE_VERSION,
            decision_id: format!("decision-{suffix}"),
            proposal_hash: proposal.commitment()?,
            evidence_hashes: vec![Digest32::from_payload(b"policy evidence")],
            outcome: DecisionOutcome::Allow,
            reason_codes: vec!["policy_allow".into()],
            decided_at_ms: 3_000,
            expires_at_ms: 10_000,
        };
        let grant = ExecutionGrant {
            version: PROFILE_VERSION,
            grant_id: format!("grant-{suffix}"),
            proposal_hash: proposal.commitment()?,
            decision_hash: decision.commitment()?,
            audience: "executor:prod-a".into(),
            not_before_ms: 3_500,
            expires_at_ms: 9_000,
            uses: 1,
            nonce: "abcdefghijklmnopqrstuvwxyz012345".into(),
        };
        Ok(Fixture {
            commitment,
            proposal,
            decision,
            grant,
            arguments,
            expected_effect,
            pre_state,
            resource_claim,
        })
    }

    fn policy() -> ExecutorPolicy {
        ExecutorPolicy {
            audience: "executor:prod-a".into(),
            authority_role: "execution_authorizer".into(),
            maximum_authority_snapshot_age_ms: 500,
            maximum_currentness_age_ms: 500,
        }
    }

    fn signer() -> Result<SigningAuthority, AuthorityError> {
        SigningAuthority::from_seed("spiffe://example.test/authority", "root-2026-09", [7; 32])
    }

    fn statement(fixture: &Fixture) -> Result<AuthorityStatement, ProtocolError> {
        Ok(AuthorityStatement {
            version: 1,
            authority_profile: AUTHORITY_PROFILE.into(),
            statement_id: format!("assertion-{}", fixture.grant.grant_id),
            issuer: "spiffe://example.test/authority".into(),
            key_id: "root-2026-09".into(),
            role: "execution_authorizer".into(),
            audience: "executor:prod-a".into(),
            record_profile: CORE_RECORD_PROFILE.into(),
            record_version: fixture.grant.version,
            record_kind: RecordKind::ExecutionGrant,
            record_digest: fixture.grant.commitment()?,
            issued_at_ms: 3_700,
            not_before_ms: 3_800,
            expires_at_ms: 8_000,
            authority_epoch: 7,
            configuration_epoch: 3,
        })
    }

    fn authority_snapshot(public_key: [u8; 32]) -> AuthoritySnapshot {
        AuthoritySnapshot {
            issuer: "spiffe://example.test/authority".into(),
            key_id: "root-2026-09".into(),
            public_key,
            authorized_roles: BTreeSet::from(["execution_authorizer".into()]),
            authorized_audiences: BTreeSet::from(["executor:prod-a".into()]),
            authority_epoch: 7,
            configuration_epoch: 3,
            key_valid_from_ms: 1_000,
            key_valid_until_ms: 10_000,
            revoked_at_ms: None,
            observed_at_ms: 3_900,
        }
    }

    fn currentness(fixture: &Fixture, version: u64) -> CurrentnessSnapshot {
        CurrentnessSnapshot {
            key: "cluster/prod/deployment/api".into(),
            version,
            policy_epoch: fixture.commitment.policy_epoch,
            configuration_epoch: fixture.commitment.configuration_epoch,
            pre_state_digest: fixture.proposal.pre_state_digest.clone(),
            resource_claim_digest: fixture.proposal.resource_claim_digest.clone(),
            revoked: false,
            observed_at_ms: 3_950 + version,
        }
    }

    fn signed_authority(
        signer: &SigningAuthority,
        fixture: &Fixture,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(signer.sign(&statement(fixture)?)?)
    }

    #[test]
    fn full_flow_releases_exact_effect_only_after_durable_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let fixture = fixture("swimming")?;
        let signer = signer()?;
        let assertion = signed_authority(&signer, &fixture)?;
        let snapshot = authority_snapshot(signer.public_key());
        let mut executor = EffectTransactionExecutor::open(root.path().join("etp.db"), policy())?;
        let claimed = executor.authorize_and_claim(
            fixture.prepared()?,
            &assertion,
            &snapshot,
            &currentness(&fixture, 1),
            "attempt-swimming",
            NOW,
        )?;
        assert_eq!(claimed.attempt_id(), "attempt-swimming");
        assert_eq!(
            claimed.authority_evidence().statement_id,
            "assertion-grant-swimming"
        );

        let capability = executor.begin_dispatch(claimed, &snapshot, NOW + 10)?;
        let (handle, observed) = capability.dispatch_with(|effect| {
            assert_eq!(effect.effect_profile(), "filesystem/canonical-write@1");
            assert_eq!(effect.operation(), "filesystem.write");
            assert_eq!(effect.target(), "workspace:/swimming.md");
            assert_eq!(effect.arguments(), fixture.arguments);
            assert_eq!(effect.expected_effect(), fixture.expected_effect);
            assert_eq!(effect.pre_state(), fixture.pre_state);
            assert_eq!(effect.resource_claim(), fixture.resource_claim);
            "adapter-returned"
        });
        assert_eq!(observed, "adapter-returned");
        let receipt_hash = executor.record_dispatched(
            handle,
            DispatchedReceipt {
                receipt_id: "receipt-swimming".into(),
                completed_at_ms: NOW + 20,
                outcome: DispatchedOutcome::Succeeded,
                observation_digest: Digest32::from_payload(b"target confirms success"),
            },
        )?;
        let lifecycle = executor.lifecycle(&fixture.grant.commitment()?)?;
        assert_eq!(
            lifecycle.receipt.as_ref().map(|value| value.outcome),
            Some(ReceiptOutcome::Succeeded)
        );
        assert_eq!(
            lifecycle
                .receipt
                .as_ref()
                .map(ProtocolRecord::commitment)
                .transpose()?,
            Some(receipt_hash)
        );
        Ok(())
    }

    #[test]
    fn every_exact_document_digest_is_enforced() -> Result<(), Box<dyn std::error::Error>> {
        for field in 0..4 {
            let fixture = fixture(&format!("digest-{field}"))?;
            let mut arguments = fixture.arguments.clone();
            let mut expected = fixture.expected_effect.clone();
            let mut pre_state = fixture.pre_state.clone();
            let mut resources = fixture.resource_claim.clone();
            [
                &mut arguments,
                &mut expected,
                &mut pre_state,
                &mut resources,
            ][field]
                .push(b'!');
            let result = PreparedEffect::new(
                fixture.commitment,
                fixture.proposal,
                fixture.decision,
                fixture.grant,
                EffectDocuments::new(arguments, expected, pre_state, resources),
            );
            assert!(matches!(
                result,
                Err(ExecutorError::DocumentDigestMismatch(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn prepared_effect_treats_profile_documents_as_opaque_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("opaque")?;
        fixture.arguments = vec![0xff, 0x00, b'{'];
        fixture.proposal.arguments_digest = Digest32::from_payload(&fixture.arguments);
        let proposal_hash = fixture.proposal.commitment()?;
        fixture.decision.proposal_hash = proposal_hash.clone();
        fixture.grant.proposal_hash = proposal_hash;
        fixture.grant.decision_hash = fixture.decision.commitment()?;

        let prepared = fixture.prepared()?;
        assert_eq!(prepared.documents.arguments, fixture.arguments);
        Ok(())
    }

    #[test]
    fn wrong_executor_audience_is_rejected_before_claim() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let fixture = fixture("audience")?;
        let signer = signer()?;
        let assertion = signed_authority(&signer, &fixture)?;
        let mut wrong_policy = policy();
        wrong_policy.audience = "executor:other".into();
        let mut executor =
            EffectTransactionExecutor::open(root.path().join("audience.db"), wrong_policy)?;
        assert!(matches!(
            executor.authorize_and_claim(
                fixture.prepared()?,
                &assertion,
                &authority_snapshot(signer.public_key()),
                &currentness(&fixture, 1),
                "attempt-audience",
                NOW,
            ),
            Err(ExecutorError::GrantAudienceMismatch)
        ));
        Ok(())
    }

    #[test]
    fn wrong_role_digest_stale_and_revoked_authority_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        enum Mutation {
            Role,
            Digest,
            Stale,
            Revoked,
        }
        for (index, mutation) in [
            Mutation::Role,
            Mutation::Digest,
            Mutation::Stale,
            Mutation::Revoked,
        ]
        .into_iter()
        .enumerate()
        {
            let root = tempfile::tempdir()?;
            let fixture = fixture(&format!("authority-{index}"))?;
            let signer = signer()?;
            let mut statement = statement(&fixture)?;
            let mut snapshot = authority_snapshot(signer.public_key());
            match mutation {
                Mutation::Role => {
                    statement.role = "other_authorizer".into();
                    snapshot.authorized_roles.insert("other_authorizer".into());
                }
                Mutation::Digest => {
                    statement.record_digest = Digest32::from_payload(b"another grant");
                }
                Mutation::Stale => snapshot.observed_at_ms = 3_000,
                Mutation::Revoked => snapshot.revoked_at_ms = Some(3_999),
            }
            let assertion = signer.sign(&statement)?;
            let mut executor =
                EffectTransactionExecutor::open(root.path().join("authority.db"), policy())?;
            let result = executor.authorize_and_claim(
                fixture.prepared()?,
                &assertion,
                &snapshot,
                &currentness(&fixture, 1),
                format!("attempt-{index}"),
                NOW,
            );
            match mutation {
                Mutation::Role => assert!(matches!(
                    result,
                    Err(ExecutorError::Authority(AuthorityError::RoleMismatch))
                )),
                Mutation::Digest => assert!(matches!(
                    result,
                    Err(ExecutorError::Authority(
                        AuthorityError::RecordDigestMismatch
                    ))
                )),
                Mutation::Stale => assert!(matches!(
                    result,
                    Err(ExecutorError::Authority(AuthorityError::StaleSnapshot))
                )),
                Mutation::Revoked => assert!(matches!(
                    result,
                    Err(ExecutorError::Authority(AuthorityError::KeyRevoked))
                )),
            }
        }
        Ok(())
    }

    #[test]
    fn authority_and_currentness_epoch_mismatches_fail_before_consumption()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let fixture = fixture("epochs")?;
        let signer = signer()?;
        let assertion = signed_authority(&signer, &fixture)?;
        let mut snapshot = authority_snapshot(signer.public_key());
        snapshot.authority_epoch += 1;
        let mut executor =
            EffectTransactionExecutor::open(root.path().join("epochs.db"), policy())?;
        assert!(matches!(
            executor.authorize_and_claim(
                fixture.prepared()?,
                &assertion,
                &snapshot,
                &currentness(&fixture, 1),
                "attempt-epoch-a",
                NOW,
            ),
            Err(ExecutorError::Authority(
                AuthorityError::AuthorityEpochMismatch
            ))
        ));

        let mut current = currentness(&fixture, 1);
        current.policy_epoch += 1;
        assert!(matches!(
            executor.authorize_and_claim(
                fixture.prepared()?,
                &assertion,
                &authority_snapshot(signer.public_key()),
                &current,
                "attempt-epoch-b",
                NOW,
            ),
            Err(ExecutorError::CurrentnessPolicyEpochMismatch)
        ));
        Ok(())
    }

    #[test]
    fn duplicate_claim_and_state_drift_cannot_reach_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let fixture = fixture("linear")?;
        let signer = signer()?;
        let assertion = signed_authority(&signer, &fixture)?;
        let snapshot = authority_snapshot(signer.public_key());
        let mut executor =
            EffectTransactionExecutor::open(root.path().join("linear.db"), policy())?;
        let claimed = executor.authorize_and_claim(
            fixture.prepared()?,
            &assertion,
            &snapshot,
            &currentness(&fixture, 1),
            "attempt-winner",
            NOW,
        )?;
        assert!(matches!(
            executor.authorize_and_claim(
                fixture.prepared()?,
                &assertion,
                &snapshot,
                &currentness(&fixture, 1),
                "attempt-loser",
                NOW + 1,
            ),
            Err(ExecutorError::Store(StoreError::GrantAlreadyClaimed))
        ));

        executor.observe_currentness(&currentness(&fixture, 2), NOW + 2)?;
        assert!(matches!(
            executor.begin_dispatch(claimed, &snapshot, NOW + 3),
            Err(ExecutorError::Store(StoreError::StaleSnapshot))
        ));
        Ok(())
    }

    #[test]
    fn authority_is_reverified_at_the_dispatch_boundary() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let fixture = fixture("dispatch-revocation")?;
        let signer = signer()?;
        let assertion = signed_authority(&signer, &fixture)?;
        let snapshot = authority_snapshot(signer.public_key());
        let mut executor =
            EffectTransactionExecutor::open(root.path().join("revocation.db"), policy())?;
        let claimed = executor.authorize_and_claim(
            fixture.prepared()?,
            &assertion,
            &snapshot,
            &currentness(&fixture, 1),
            "attempt-revoked-after-claim",
            NOW,
        )?;
        let grant_hash = claimed.grant_hash().clone();

        let mut revoked = snapshot;
        revoked.revoked_at_ms = Some(NOW + 1);
        revoked.observed_at_ms = NOW + 1;
        assert!(matches!(
            executor.begin_dispatch(claimed, &revoked, NOW + 2),
            Err(ExecutorError::Authority(AuthorityError::KeyRevoked))
        ));
        assert_eq!(
            executor
                .lifecycle(&grant_hash)?
                .claim
                .and_then(|claim| claim.dispatch_started_at_ms),
            None
        );
        Ok(())
    }

    #[test]
    fn post_marker_crash_recovers_only_as_unknown_then_reconciles()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("crash.db");
        let fixture = fixture("crash")?;
        let signer = signer()?;
        let assertion = signed_authority(&signer, &fixture)?;
        let grant_hash;
        let proposal_hash;
        {
            let mut executor = EffectTransactionExecutor::open(&path, policy())?;
            let claimed = executor.authorize_and_claim(
                fixture.prepared()?,
                &assertion,
                &authority_snapshot(signer.public_key()),
                &currentness(&fixture, 1),
                "attempt-crash",
                NOW,
            )?;
            grant_hash = claimed.grant_hash().clone();
            proposal_hash = claimed.proposal_hash().clone();
            let dispatch_snapshot = authority_snapshot(signer.public_key());
            let _marker_without_result =
                executor.begin_dispatch(claimed, &dispatch_snapshot, NOW + 10)?;
        }

        let mut reopened = EffectTransactionExecutor::open(&path, policy())?;
        assert!(matches!(
            reopened.record_recovered_not_dispatched(NotDispatchedRecovery {
                receipt_id: "receipt-invalid-not-dispatched".into(),
                proposal_hash: proposal_hash.clone(),
                grant_hash: grant_hash.clone(),
                attempt_id: "attempt-crash".into(),
                completed_at_ms: NOW + 40,
                observation_digest: Digest32::from_payload(b"invalid certainty"),
            }),
            Err(ExecutorError::UnexpectedDispatchMarker)
        ));
        let receipt_hash = reopened.record_recovered_unknown(UnknownRecovery {
            receipt_id: "receipt-crash".into(),
            proposal_hash,
            grant_hash: grant_hash.clone(),
            attempt_id: "attempt-crash".into(),
            completed_at_ms: NOW + 50,
            observation_digest: Digest32::from_payload(b"transport outcome unavailable"),
        })?;
        assert_eq!(
            reopened
                .lifecycle(&grant_hash)?
                .receipt
                .as_ref()
                .map(|value| value.outcome),
            Some(ReceiptOutcome::Unknown)
        );
        let reconciliation = ReconciliationRecord {
            version: 1,
            reconciliation_id: "reconciliation-crash-1".into(),
            receipt_hash,
            sequence: 1,
            parent_reconciliation_hash: None,
            observed_at_ms: NOW + 100,
            outcome: ReconciliationOutcome::EffectConfirmed,
            evidence_digest: Digest32::from_payload(b"target idempotency record found"),
        };
        reopened.append_reconciliation(&reconciliation)?;
        assert_eq!(reopened.lifecycle(&grant_hash)?.reconciliations.len(), 1);
        Ok(())
    }

    #[test]
    fn recovery_refuses_unknown_without_dispatch_marker() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let path = root.path().join("no-marker.db");
        let fixture = fixture("no-marker")?;
        let signer = signer()?;
        let assertion = signed_authority(&signer, &fixture)?;
        let proposal_hash;
        let grant_hash;
        {
            let mut executor = EffectTransactionExecutor::open(&path, policy())?;
            let claimed = executor.authorize_and_claim(
                fixture.prepared()?,
                &assertion,
                &authority_snapshot(signer.public_key()),
                &currentness(&fixture, 1),
                "attempt-no-marker",
                NOW,
            )?;
            proposal_hash = claimed.proposal_hash().clone();
            grant_hash = claimed.grant_hash().clone();
        }

        let mut reopened = EffectTransactionExecutor::open(&path, policy())?;
        assert!(matches!(
            reopened.record_recovered_unknown(UnknownRecovery {
                receipt_id: "receipt-invalid-unknown".into(),
                proposal_hash: proposal_hash.clone(),
                grant_hash: grant_hash.clone(),
                attempt_id: "attempt-no-marker".into(),
                completed_at_ms: NOW + 10,
                observation_digest: Digest32::from_payload(b"none"),
            }),
            Err(ExecutorError::MissingDispatchMarker)
        ));
        reopened.record_recovered_not_dispatched(NotDispatchedRecovery {
            receipt_id: "receipt-not-dispatched".into(),
            proposal_hash,
            grant_hash: grant_hash.clone(),
            attempt_id: "attempt-no-marker".into(),
            completed_at_ms: NOW + 10,
            observation_digest: Digest32::from_payload(b"adapter never invoked"),
        })?;
        assert_eq!(
            reopened
                .lifecycle(&grant_hash)?
                .receipt
                .as_ref()
                .map(|receipt| receipt.outcome),
            Some(ReceiptOutcome::NotDispatched)
        );
        Ok(())
    }
}

//! Durable single-node lifecycle storage for ETP records.

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Duration;

use effect_transaction_core::{
    AuthorizationDecision, Digest32, EffectProposal, EffectReceipt, ExecutionGrant,
    MAX_RECONCILIATION_RECORDS, MAX_SAFE_INTEGER, ProtocolError, ProtocolRecord, ReceiptOutcome,
    ReconciliationRecord, TaskCommitment, canonical_json, parse_record, verify_chain, verify_grant,
    verify_reconciliation,
};
use rusqlite::{
    Connection, ErrorCode, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x4554_5031;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum target-currentness age that a caller can select.
pub const MAX_CURRENTNESS_AGE_MS: u64 = 300_000;

const SCHEMA: &str = r"
BEGIN IMMEDIATE;
CREATE TABLE store_meta (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    last_trusted_time_ms INTEGER
) STRICT;
INSERT INTO store_meta(singleton, last_trusted_time_ms) VALUES (1, NULL);

CREATE TABLE currentness (
    currentness_key TEXT PRIMARY KEY NOT NULL,
    snapshot_version INTEGER NOT NULL CHECK (snapshot_version > 0),
    policy_epoch INTEGER NOT NULL CHECK (policy_epoch >= 0),
    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch >= 0),
    pre_state_digest TEXT NOT NULL,
    resource_claim_digest TEXT NOT NULL,
    revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0)
) STRICT;

CREATE TABLE authorization_chains (
    grant_id TEXT PRIMARY KEY NOT NULL,
    grant_hash TEXT NOT NULL UNIQUE,
    proposal_hash TEXT NOT NULL UNIQUE,
    decision_hash TEXT NOT NULL UNIQUE,
    commitment_json BLOB NOT NULL,
    proposal_json BLOB NOT NULL,
    decision_json BLOB NOT NULL,
    grant_json BLOB NOT NULL
) STRICT;

CREATE TABLE claims (
    grant_hash TEXT PRIMARY KEY NOT NULL
        REFERENCES authorization_chains(grant_hash),
    attempt_id TEXT NOT NULL UNIQUE,
    currentness_key TEXT NOT NULL REFERENCES currentness(currentness_key),
    snapshot_version INTEGER NOT NULL,
    maximum_snapshot_age_ms INTEGER NOT NULL CHECK (maximum_snapshot_age_ms > 0),
    claimed_at_ms INTEGER NOT NULL,
    dispatch_started_at_ms INTEGER,
    CHECK (dispatch_started_at_ms IS NULL OR dispatch_started_at_ms >= claimed_at_ms)
) STRICT;

CREATE TABLE receipts (
    grant_hash TEXT PRIMARY KEY NOT NULL REFERENCES claims(grant_hash),
    receipt_id TEXT NOT NULL UNIQUE,
    receipt_hash TEXT NOT NULL UNIQUE,
    receipt_json BLOB NOT NULL
) STRICT;

CREATE TABLE reconciliations (
    receipt_hash TEXT NOT NULL REFERENCES receipts(receipt_hash),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    reconciliation_id TEXT NOT NULL UNIQUE,
    reconciliation_hash TEXT NOT NULL UNIQUE,
    parent_reconciliation_hash TEXT UNIQUE,
    record_json BLOB NOT NULL,
    PRIMARY KEY (receipt_hash, sequence)
) STRICT;

CREATE TRIGGER authorization_chains_no_update BEFORE UPDATE ON authorization_chains
BEGIN SELECT RAISE(ABORT, 'append-only authorization chain'); END;
CREATE TRIGGER authorization_chains_no_delete BEFORE DELETE ON authorization_chains
BEGIN SELECT RAISE(ABORT, 'append-only authorization chain'); END;
CREATE TRIGGER claims_update_guard BEFORE UPDATE ON claims
WHEN NEW.grant_hash IS NOT OLD.grant_hash
  OR NEW.attempt_id IS NOT OLD.attempt_id
  OR NEW.currentness_key IS NOT OLD.currentness_key
  OR NEW.snapshot_version IS NOT OLD.snapshot_version
  OR NEW.maximum_snapshot_age_ms IS NOT OLD.maximum_snapshot_age_ms
  OR NEW.claimed_at_ms IS NOT OLD.claimed_at_ms
  OR OLD.dispatch_started_at_ms IS NOT NULL
  OR NEW.dispatch_started_at_ms IS NULL
BEGIN SELECT RAISE(ABORT, 'claim is immutable except for its first dispatch marker'); END;
CREATE TRIGGER claims_no_delete BEFORE DELETE ON claims
BEGIN SELECT RAISE(ABORT, 'append-only claim'); END;
CREATE TRIGGER receipts_no_update BEFORE UPDATE ON receipts
BEGIN SELECT RAISE(ABORT, 'append-only receipt'); END;
CREATE TRIGGER receipts_no_delete BEFORE DELETE ON receipts
BEGIN SELECT RAISE(ABORT, 'append-only receipt'); END;
CREATE TRIGGER reconciliations_no_update BEFORE UPDATE ON reconciliations
BEGIN SELECT RAISE(ABORT, 'append-only reconciliation'); END;
CREATE TRIGGER reconciliations_no_delete BEFORE DELETE ON reconciliations
BEGIN SELECT RAISE(ABORT, 'append-only reconciliation'); END;

PRAGMA application_id = 1163153457;
PRAGMA user_version = 1;
COMMIT;
";

/// Authority and target state used to claim a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentnessSnapshot {
    pub key: String,
    pub version: u64,
    pub policy_epoch: u64,
    pub configuration_epoch: u64,
    pub pre_state_digest: Digest32,
    pub resource_claim_digest: Digest32,
    pub revoked: bool,
    pub observed_at_ms: u64,
}

/// Claim inputs that are not stored in the currentness record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimRequest {
    pub attempt_id: String,
    pub expected_audience: String,
    pub currentness_key: String,
    pub expected_snapshot_version: u64,
    pub maximum_snapshot_age_ms: u64,
}

/// The durable winning claim for a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableClaim {
    pub grant_hash: Digest32,
    pub attempt_id: String,
    pub currentness_key: String,
    pub snapshot_version: u64,
    pub maximum_snapshot_age_ms: u64,
    pub claimed_at_ms: u64,
    pub dispatch_started_at_ms: Option<u64>,
}

/// A durable marker written before the caller starts external dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchMarker {
    pub grant_hash: Digest32,
    pub attempt_id: String,
    pub dispatched_at_ms: u64,
}

/// A read-only lifecycle reconstructed from durable rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifecycle {
    pub grant_hash: Digest32,
    pub claim: Option<DurableClaim>,
    pub receipt: Option<EffectReceipt>,
    pub reconciliations: Vec<ReconciliationRecord>,
}

/// Errors returned by the `SQLite` lifecycle store.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("protocol validation failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("storage is unavailable")]
    Unavailable,
    #[error("database integrity check failed")]
    Corrupt,
    #[error("database schema is incompatible")]
    IncompatibleSchema,
    #[error("non-empty database has no schema version")]
    ForeignDatabase,
    #[error("invalid store input: {0}")]
    InvalidInput(&'static str),
    #[error("grant identifier is bound to a different chain")]
    GrantConflict,
    #[error("proposal already issued another grant")]
    ProposalAlreadyGranted,
    #[error("decision already issued another grant")]
    DecisionAlreadyGranted,
    #[error("unknown grant")]
    UnknownGrant,
    #[error("unknown currentness snapshot")]
    UnknownCurrentness,
    #[error("currentness version did not advance monotonically")]
    CurrentnessVersionConflict,
    #[error("authority epochs moved backwards")]
    AuthorityEpochRollback,
    #[error("trusted observation time moved backwards")]
    ObservationRollback,
    #[error("revocation cannot be cleared without a newer authority epoch")]
    RevocationRollback,
    #[error("trusted time moved backwards")]
    ClockRollback,
    #[error("expected currentness version is stale")]
    StaleSnapshot,
    #[error("currentness snapshot is from the future")]
    SnapshotFromFuture,
    #[error("currentness snapshot is stale")]
    StaleCurrentness,
    #[error("grant audience mismatch")]
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
    #[error("grant has expired")]
    GrantExpired,
    #[error("grant was already claimed")]
    GrantAlreadyClaimed,
    #[error("attempt identifier was already used")]
    AttemptAlreadyUsed,
    #[error("claim does not match the winning attempt")]
    ClaimMismatch,
    #[error("dispatch was already marked at a different time")]
    DispatchAlreadyStarted,
    #[error("receipt dispatch evidence conflicts with the durable dispatch marker")]
    DispatchEvidenceMismatch,
    #[error("ledger receipt conflicts with the stored receipt")]
    ReceiptConflict,
    #[error("unknown receipt")]
    UnknownReceipt,
    #[error("reconciliation would fork the authoritative history")]
    ReconciliationFork,
    #[error("reconciliation identifier was already used")]
    ReconciliationIdentifierConflict,
}

/// Durable ETP lifecycle store backed by one `SQLite` connection.
pub struct SqliteEffectStore {
    connection: Connection,
}

impl std::fmt::Debug for SqliteEffectStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteEffectStore")
            .finish_non_exhaustive()
    }
}

impl SqliteEffectStore {
    /// Opens or creates a store.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, an incompatible schema, failed
    /// integrity checks, or unavailable storage.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        if path.as_ref().as_os_str().is_empty() {
            return Err(StoreError::InvalidInput("database path"));
        }
        let connection = Connection::open(path).map_err(map_sqlite)?;
        connection.busy_timeout(BUSY_TIMEOUT).map_err(map_sqlite)?;
        preflight_schema(&connection)?;
        configure(&connection)?;
        initialize_or_verify_schema(&connection)?;
        Ok(Self { connection })
    }

    /// Registers one verified authorization chain.
    ///
    /// Repeating the same registration is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid chain, a conflicting binding, or
    /// unavailable storage.
    pub fn register_chain(
        &mut self,
        commitment: &TaskCommitment,
        proposal: &EffectProposal,
        decision: &AuthorizationDecision,
        grant: &ExecutionGrant,
    ) -> Result<Digest32, StoreError> {
        let grant_hash = verify_grant(commitment, proposal, decision, grant)?;
        let proposal_hash = proposal.commitment()?;
        let decision_hash = decision.commitment()?;
        let commitment_json = canonical_json(commitment)?;
        let proposal_json = canonical_json(proposal)?;
        let decision_json = canonical_json(decision)?;
        let grant_json = canonical_json(grant)?;

        let transaction = immediate(&mut self.connection)?;
        if let Some(existing) = load_raw_chain_by_id(&transaction, &grant.grant_id)? {
            if existing.grant_hash == grant_hash.as_str()
                && existing.proposal_hash == proposal_hash.as_str()
                && existing.decision_hash == decision_hash.as_str()
                && existing.commitment_json == commitment_json
                && existing.proposal_json == proposal_json
                && existing.decision_json == decision_json
                && existing.grant_json == grant_json
            {
                transaction.commit().map_err(map_sqlite)?;
                return Ok(grant_hash);
            }
            return Err(StoreError::GrantConflict);
        }
        if exists(&transaction, "proposal_hash", proposal_hash.as_str())? {
            return Err(StoreError::ProposalAlreadyGranted);
        }
        if exists(&transaction, "decision_hash", decision_hash.as_str())? {
            return Err(StoreError::DecisionAlreadyGranted);
        }
        transaction
            .execute(
                "INSERT INTO authorization_chains (
                    grant_id, grant_hash, proposal_hash, decision_hash,
                    commitment_json, proposal_json, decision_json, grant_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    grant.grant_id,
                    grant_hash.as_str(),
                    proposal_hash.as_str(),
                    decision_hash.as_str(),
                    commitment_json,
                    proposal_json,
                    decision_json,
                    grant_json
                ],
            )
            .map_err(map_sqlite)?;
        transaction.commit().map_err(map_sqlite)?;
        Ok(grant_hash)
    }

    /// Inserts or advances a monotonic currentness record.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, a monotonicity or revocation conflict,
    /// or unavailable storage. A rejected update does not change the stored
    /// record.
    pub fn put_currentness(&mut self, snapshot: &CurrentnessSnapshot) -> Result<(), StoreError> {
        validate_snapshot(snapshot)?;
        let transaction = immediate(&mut self.connection)?;
        let existing = load_currentness(&transaction, &snapshot.key)?;
        if let Some(previous) = existing {
            if previous == *snapshot {
                transaction.commit().map_err(map_sqlite)?;
                return Ok(());
            }
            if snapshot.version <= previous.version {
                return Err(StoreError::CurrentnessVersionConflict);
            }
            if snapshot.policy_epoch < previous.policy_epoch
                || snapshot.configuration_epoch < previous.configuration_epoch
            {
                return Err(StoreError::AuthorityEpochRollback);
            }
            if snapshot.observed_at_ms < previous.observed_at_ms {
                return Err(StoreError::ObservationRollback);
            }
            if previous.revoked
                && !snapshot.revoked
                && snapshot.policy_epoch == previous.policy_epoch
                && snapshot.configuration_epoch == previous.configuration_epoch
            {
                return Err(StoreError::RevocationRollback);
            }
            transaction
                .execute(
                    "UPDATE currentness SET
                        snapshot_version=?2, policy_epoch=?3, configuration_epoch=?4,
                        pre_state_digest=?5, resource_claim_digest=?6, revoked=?7,
                        observed_at_ms=?8 WHERE currentness_key=?1",
                    snapshot_params(snapshot)?,
                )
                .map_err(map_sqlite)?;
        } else {
            transaction
                .execute(
                    "INSERT INTO currentness (
                        currentness_key, snapshot_version, policy_epoch, configuration_epoch,
                        pre_state_digest, resource_claim_digest, revoked, observed_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    snapshot_params(snapshot)?,
                )
                .map_err(map_sqlite)?;
        }
        transaction.commit().map_err(map_sqlite)
    }

    /// Checks currentness and atomically claims one grant.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, stale or revoked authority, invalid
    /// time or audience, a prior claim, failed integrity checks, or unavailable
    /// storage.
    pub fn claim(
        &mut self,
        grant: &ExecutionGrant,
        request: &ClaimRequest,
        trusted_now_ms: u64,
    ) -> Result<DurableClaim, StoreError> {
        validate_claim_request(request)?;
        safe_i64(trusted_now_ms, "trusted_now_ms")?;
        let supplied_hash = grant.commitment()?;
        let transaction = immediate(&mut self.connection)?;
        let chain = load_chain_by_grant_id(&transaction, &grant.grant_id)?
            .ok_or(StoreError::UnknownGrant)?;
        if chain.grant_hash != supplied_hash || chain.grant != *grant {
            return Err(StoreError::GrantConflict);
        }
        verify_grant(
            &chain.commitment,
            &chain.proposal,
            &chain.decision,
            &chain.grant,
        )?;
        let last_time = transaction
            .query_row(
                "SELECT last_trusted_time_ms FROM store_meta WHERE singleton=1",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(map_sqlite)?;
        let now = safe_i64(trusted_now_ms, "trusted_now_ms")?;
        if last_time.is_some_and(|last| now < last) {
            return Err(StoreError::ClockRollback);
        }
        let snapshot = load_currentness(&transaction, &request.currentness_key)?
            .ok_or(StoreError::UnknownCurrentness)?;
        validate_currentness_age(&snapshot, trusted_now_ms, request.maximum_snapshot_age_ms)?;
        if snapshot.version != request.expected_snapshot_version {
            return Err(StoreError::StaleSnapshot);
        }
        if request.expected_audience != chain.grant.audience {
            return Err(StoreError::AudienceMismatch);
        }
        if snapshot.policy_epoch != chain.commitment.policy_epoch
            || snapshot.configuration_epoch != chain.commitment.configuration_epoch
        {
            return Err(StoreError::StaleAuthority);
        }
        if snapshot.pre_state_digest != chain.proposal.pre_state_digest {
            return Err(StoreError::StalePreState);
        }
        if snapshot.resource_claim_digest != chain.proposal.resource_claim_digest {
            return Err(StoreError::StaleResourceClaim);
        }
        if snapshot.revoked {
            return Err(StoreError::GrantRevoked);
        }
        if trusted_now_ms < chain.grant.not_before_ms {
            return Err(StoreError::GrantNotYetValid);
        }
        if trusted_now_ms >= chain.grant.expires_at_ms {
            return Err(StoreError::GrantExpired);
        }
        transaction
            .execute(
                "UPDATE store_meta SET last_trusted_time_ms=?1 WHERE singleton=1",
                [now],
            )
            .map_err(map_sqlite)?;
        match transaction.execute(
            "INSERT INTO claims (
                grant_hash, attempt_id, currentness_key, snapshot_version,
                maximum_snapshot_age_ms, claimed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                supplied_hash.as_str(),
                request.attempt_id,
                request.currentness_key,
                safe_i64(request.expected_snapshot_version, "snapshot version")?,
                safe_i64(request.maximum_snapshot_age_ms, "maximum snapshot age")?,
                now
            ],
        ) {
            Ok(_) => {}
            Err(error) if is_constraint(&error) => {
                if claim_exists(&transaction, supplied_hash.as_str())? {
                    return Err(StoreError::GrantAlreadyClaimed);
                }
                return Err(StoreError::AttemptAlreadyUsed);
            }
            Err(error) => return Err(map_sqlite(error)),
        }
        transaction.commit().map_err(map_sqlite)?;
        Ok(DurableClaim {
            grant_hash: supplied_hash,
            attempt_id: request.attempt_id.clone(),
            currentness_key: request.currentness_key.clone(),
            snapshot_version: request.expected_snapshot_version,
            maximum_snapshot_age_ms: request.maximum_snapshot_age_ms,
            claimed_at_ms: trusted_now_ms,
            dispatch_started_at_ms: None,
        })
    }

    /// Writes a durable marker before external dispatch starts.
    ///
    /// Repeating the same marker write is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or mismatched claim, invalid time,
    /// conflicting marker, or unavailable storage.
    pub fn mark_dispatch_started(
        &mut self,
        grant_hash: &Digest32,
        attempt_id: &str,
        dispatched_at_ms: u64,
    ) -> Result<DispatchMarker, StoreError> {
        validate_text("attempt_id", attempt_id, 256)?;
        let dispatched = safe_i64(dispatched_at_ms, "dispatched_at_ms")?;
        let transaction = immediate(&mut self.connection)?;
        let claim =
            load_claim(&transaction, grant_hash.as_str())?.ok_or(StoreError::UnknownGrant)?;
        if claim.attempt_id != attempt_id {
            return Err(StoreError::ClaimMismatch);
        }
        if dispatched_at_ms < claim.claimed_at_ms {
            return Err(StoreError::InvalidInput("dispatch predates claim"));
        }
        if let Some(existing) = claim.dispatch_started_at_ms {
            if existing == dispatched_at_ms {
                transaction.commit().map_err(map_sqlite)?;
                return Ok(DispatchMarker {
                    grant_hash: grant_hash.clone(),
                    attempt_id: attempt_id.to_owned(),
                    dispatched_at_ms,
                });
            }
            return Err(StoreError::DispatchAlreadyStarted);
        }
        let last_time = transaction
            .query_row(
                "SELECT last_trusted_time_ms FROM store_meta WHERE singleton=1",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .map_err(map_sqlite)?;
        if last_time.is_some_and(|last| dispatched < last) {
            return Err(StoreError::ClockRollback);
        }
        let chain = load_chain_by_grant_hash(&transaction, grant_hash.as_str())?
            .ok_or(StoreError::UnknownGrant)?;
        if dispatched_at_ms >= chain.grant.expires_at_ms {
            return Err(StoreError::GrantExpired);
        }
        let snapshot = load_currentness(&transaction, &claim.currentness_key)?
            .ok_or(StoreError::UnknownCurrentness)?;
        validate_currentness_age(&snapshot, dispatched_at_ms, claim.maximum_snapshot_age_ms)?;
        if snapshot.version != claim.snapshot_version {
            return Err(StoreError::StaleSnapshot);
        }
        if snapshot.policy_epoch != chain.commitment.policy_epoch
            || snapshot.configuration_epoch != chain.commitment.configuration_epoch
        {
            return Err(StoreError::StaleAuthority);
        }
        if snapshot.pre_state_digest != chain.proposal.pre_state_digest {
            return Err(StoreError::StalePreState);
        }
        if snapshot.resource_claim_digest != chain.proposal.resource_claim_digest {
            return Err(StoreError::StaleResourceClaim);
        }
        if snapshot.revoked {
            return Err(StoreError::GrantRevoked);
        }
        transaction
            .execute(
                "UPDATE store_meta SET last_trusted_time_ms=?1 WHERE singleton=1",
                [dispatched],
            )
            .map_err(map_sqlite)?;
        transaction
            .execute(
                "UPDATE claims SET dispatch_started_at_ms=?1
                 WHERE grant_hash=?2 AND attempt_id=?3 AND dispatch_started_at_ms IS NULL",
                params![dispatched, grant_hash.as_str(), attempt_id],
            )
            .map_err(map_sqlite)?;
        transaction.commit().map_err(map_sqlite)?;
        Ok(DispatchMarker {
            grant_hash: grant_hash.clone(),
            attempt_id: attempt_id.to_owned(),
            dispatched_at_ms,
        })
    }

    /// Records the ledger receipt for the winning attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid chain, claim or dispatch mismatch,
    /// receipt conflict, failed integrity check, or unavailable storage.
    pub fn record_receipt(&mut self, receipt: &EffectReceipt) -> Result<Digest32, StoreError> {
        receipt.validate()?;
        let receipt_hash = receipt.commitment()?;
        let transaction = immediate(&mut self.connection)?;
        let chain = load_chain_by_grant_hash(&transaction, receipt.grant_hash.as_str())?
            .ok_or(StoreError::UnknownGrant)?;
        let verified = verify_chain(
            &chain.commitment,
            &chain.proposal,
            &chain.decision,
            &chain.grant,
            receipt,
        )?;
        let claim = load_claim(&transaction, receipt.grant_hash.as_str())?
            .ok_or(StoreError::ClaimMismatch)?;
        if claim.attempt_id != receipt.attempt_id || claim.claimed_at_ms != receipt.claimed_at_ms {
            return Err(StoreError::ClaimMismatch);
        }
        validate_dispatch_evidence(receipt, claim.dispatch_started_at_ms)?;
        if let Some(existing) = load_receipt_by_grant(&transaction, receipt.grant_hash.as_str())? {
            if existing.commitment()? == receipt_hash {
                transaction.commit().map_err(map_sqlite)?;
                return Ok(receipt_hash);
            }
            return Err(StoreError::ReceiptConflict);
        }
        let receipt_json = canonical_json(receipt)?;
        transaction
            .execute(
                "INSERT INTO receipts (grant_hash, receipt_id, receipt_hash, receipt_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    verified.grant_hash.as_str(),
                    receipt.receipt_id,
                    receipt_hash.as_str(),
                    receipt_json
                ],
            )
            .map_err(|error| {
                if is_constraint(&error) {
                    StoreError::ReceiptConflict
                } else {
                    map_sqlite(error)
                }
            })?;
        transaction.commit().map_err(map_sqlite)?;
        Ok(receipt_hash)
    }

    /// Appends a parent-linked reconciliation record.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid record, unknown receipt, fork, identifier
    /// conflict, resource limit, failed integrity check, or unavailable storage.
    pub fn append_reconciliation(
        &mut self,
        record: &ReconciliationRecord,
    ) -> Result<Digest32, StoreError> {
        record.validate()?;
        let record_hash = record.commitment()?;
        let transaction = immediate(&mut self.connection)?;
        let receipt = load_receipt_by_hash(&transaction, record.receipt_hash.as_str())?
            .ok_or(StoreError::UnknownReceipt)?;
        if let Some(existing) =
            load_reconciliation_at(&transaction, record.receipt_hash.as_str(), record.sequence)?
        {
            if existing.commitment()? == record_hash {
                transaction.commit().map_err(map_sqlite)?;
                return Ok(record_hash);
            }
            return Err(StoreError::ReconciliationFork);
        }
        let count = reconciliation_count(&transaction, record.receipt_hash.as_str())?;
        if count >= MAX_RECONCILIATION_RECORDS {
            return Err(StoreError::Protocol(ProtocolError::ResourceLimit(
                "reconciliation records",
            )));
        }
        let previous = load_latest_reconciliation(&transaction, record.receipt_hash.as_str())?;
        let verified_hash = verify_reconciliation(&receipt, previous.as_ref(), record)?;
        let record_json = canonical_json(record)?;
        match transaction.execute(
            "INSERT INTO reconciliations (
                receipt_hash, sequence, reconciliation_id, reconciliation_hash,
                parent_reconciliation_hash, record_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.receipt_hash.as_str(),
                safe_i64(record.sequence, "reconciliation sequence")?,
                record.reconciliation_id,
                verified_hash.as_str(),
                record
                    .parent_reconciliation_hash
                    .as_ref()
                    .map(Digest32::as_str),
                record_json
            ],
        ) {
            Ok(_) => {}
            Err(error) if is_constraint(&error) => {
                if reconciliation_id_exists(&transaction, &record.reconciliation_id)? {
                    return Err(StoreError::ReconciliationIdentifierConflict);
                }
                return Err(StoreError::ReconciliationFork);
            }
            Err(error) => return Err(map_sqlite(error)),
        }
        transaction.commit().map_err(map_sqlite)?;
        Ok(record_hash)
    }

    /// Reads the durable lifecycle of a registered grant.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown grant, invalid stored data, failed
    /// integrity checks, or unavailable storage.
    pub fn lifecycle(&self, grant_hash: &Digest32) -> Result<Lifecycle, StoreError> {
        let chain = load_chain_by_grant_hash_connection(&self.connection, grant_hash.as_str())?
            .ok_or(StoreError::UnknownGrant)?;
        let claim = load_claim_connection(&self.connection, grant_hash.as_str())?;
        let receipt = load_receipt_by_grant_connection(&self.connection, grant_hash.as_str())?;
        let reconciliations = if let Some(value) = &receipt {
            verify_chain(
                &chain.commitment,
                &chain.proposal,
                &chain.decision,
                &chain.grant,
                value,
            )?;
            let winning_claim = claim.as_ref().ok_or(StoreError::Corrupt)?;
            if winning_claim.attempt_id != value.attempt_id
                || winning_claim.claimed_at_ms != value.claimed_at_ms
            {
                return Err(StoreError::Corrupt);
            }
            validate_dispatch_evidence(value, winning_claim.dispatch_started_at_ms)?;
            let records = load_all_reconciliations(&self.connection, value.commitment()?.as_str())?;
            let mut previous = None;
            for record in &records {
                verify_reconciliation(value, previous, record)?;
                previous = Some(record);
            }
            records
        } else {
            Vec::new()
        };
        Ok(Lifecycle {
            grant_hash: grant_hash.clone(),
            claim,
            receipt,
            reconciliations,
        })
    }
}

#[derive(Debug)]
struct RawChain {
    grant_hash: String,
    proposal_hash: String,
    decision_hash: String,
    commitment_json: Vec<u8>,
    proposal_json: Vec<u8>,
    decision_json: Vec<u8>,
    grant_json: Vec<u8>,
}

#[derive(Debug)]
struct StoredChain {
    grant_hash: Digest32,
    commitment: TaskCommitment,
    proposal: EffectProposal,
    decision: AuthorizationDecision,
    grant: ExecutionGrant,
}

fn configure(connection: &Connection) -> Result<(), StoreError> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA trusted_schema=OFF;
             PRAGMA secure_delete=ON;",
        )
        .map_err(map_sqlite)?;
    let journal = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(map_sqlite)?;
    let foreign_keys = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite)?;
    let synchronous = connection
        .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite)?;
    if !journal.eq_ignore_ascii_case("wal") || foreign_keys != 1 || synchronous != 2 {
        return Err(StoreError::Unavailable);
    }
    Ok(())
}

fn preflight_schema(connection: &Connection) -> Result<(), StoreError> {
    let version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite)?;
    if version == 0 {
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(map_sqlite)?;
        if count != 0 {
            return Err(StoreError::ForeignDatabase);
        }
    } else {
        if version != SCHEMA_VERSION {
            return Err(StoreError::IncompatibleSchema);
        }
        let application_id = connection
            .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
            .map_err(map_sqlite)?;
        if application_id != APPLICATION_ID {
            return Err(StoreError::IncompatibleSchema);
        }
    }
    Ok(())
}

fn initialize_or_verify_schema(connection: &Connection) -> Result<(), StoreError> {
    let version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite)?;
    if version == 0 {
        connection.execute_batch(SCHEMA).map_err(map_sqlite)?;
    }
    let application_id = connection
        .query_row("PRAGMA application_id", [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite)?;
    if application_id != APPLICATION_ID {
        return Err(StoreError::IncompatibleSchema);
    }
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(map_sqlite)?;
    if integrity != "ok" {
        return Err(StoreError::Corrupt);
    }
    verify_schema_objects(connection)?;
    Ok(())
}

fn verify_schema_objects(connection: &Connection) -> Result<(), StoreError> {
    const OBJECTS: &[(&str, &str)] = &[
        ("table", "store_meta"),
        ("table", "currentness"),
        ("table", "authorization_chains"),
        ("table", "claims"),
        ("table", "receipts"),
        ("table", "reconciliations"),
        ("trigger", "authorization_chains_no_update"),
        ("trigger", "authorization_chains_no_delete"),
        ("trigger", "claims_update_guard"),
        ("trigger", "claims_no_delete"),
        ("trigger", "receipts_no_update"),
        ("trigger", "receipts_no_delete"),
        ("trigger", "reconciliations_no_update"),
        ("trigger", "reconciliations_no_delete"),
    ];
    for (object_type, name) in OBJECTS {
        let found = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type=?1 AND name=?2 AND sql IS NOT NULL",
                params![object_type, name],
                |_| Ok(()),
            )
            .optional()
            .map_err(map_sqlite)?;
        if found.is_none() {
            return Err(StoreError::IncompatibleSchema);
        }
    }
    Ok(())
}

fn immediate(connection: &mut Connection) -> Result<Transaction<'_>, StoreError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sqlite)
}

fn validate_snapshot(snapshot: &CurrentnessSnapshot) -> Result<(), StoreError> {
    validate_text("currentness key", &snapshot.key, 1_024)?;
    if snapshot.version == 0 {
        return Err(StoreError::InvalidInput("snapshot version"));
    }
    safe_i64(snapshot.version, "snapshot version")?;
    safe_i64(snapshot.policy_epoch, "policy epoch")?;
    safe_i64(snapshot.configuration_epoch, "configuration epoch")?;
    safe_i64(snapshot.observed_at_ms, "observed_at_ms")?;
    Ok(())
}

fn validate_claim_request(request: &ClaimRequest) -> Result<(), StoreError> {
    validate_text("attempt_id", &request.attempt_id, 256)?;
    validate_text("expected_audience", &request.expected_audience, 512)?;
    validate_text("currentness_key", &request.currentness_key, 1_024)?;
    if request.expected_snapshot_version == 0 {
        return Err(StoreError::InvalidInput("snapshot version"));
    }
    safe_i64(request.expected_snapshot_version, "snapshot version")?;
    if request.maximum_snapshot_age_ms == 0
        || request.maximum_snapshot_age_ms > MAX_CURRENTNESS_AGE_MS
    {
        return Err(StoreError::InvalidInput("maximum snapshot age"));
    }
    safe_i64(request.maximum_snapshot_age_ms, "maximum snapshot age")?;
    Ok(())
}

fn validate_currentness_age(
    snapshot: &CurrentnessSnapshot,
    trusted_now_ms: u64,
    maximum_snapshot_age_ms: u64,
) -> Result<(), StoreError> {
    if snapshot.observed_at_ms > trusted_now_ms {
        return Err(StoreError::SnapshotFromFuture);
    }
    if trusted_now_ms - snapshot.observed_at_ms > maximum_snapshot_age_ms {
        return Err(StoreError::StaleCurrentness);
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidInput(field));
    }
    Ok(())
}

fn safe_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    if value > MAX_SAFE_INTEGER {
        return Err(StoreError::InvalidInput(field));
    }
    i64::try_from(value).map_err(|_| StoreError::InvalidInput(field))
}

fn snapshot_params(
    snapshot: &CurrentnessSnapshot,
) -> Result<[rusqlite::types::Value; 8], StoreError> {
    use rusqlite::types::Value;
    Ok([
        Value::Text(snapshot.key.clone()),
        Value::Integer(safe_i64(snapshot.version, "snapshot version")?),
        Value::Integer(safe_i64(snapshot.policy_epoch, "policy epoch")?),
        Value::Integer(safe_i64(
            snapshot.configuration_epoch,
            "configuration epoch",
        )?),
        Value::Text(snapshot.pre_state_digest.as_str().to_owned()),
        Value::Text(snapshot.resource_claim_digest.as_str().to_owned()),
        Value::Integer(i64::from(snapshot.revoked)),
        Value::Integer(safe_i64(snapshot.observed_at_ms, "observed_at_ms")?),
    ])
}

fn load_currentness(
    transaction: &Transaction<'_>,
    key: &str,
) -> Result<Option<CurrentnessSnapshot>, StoreError> {
    transaction
        .query_row(
            "SELECT snapshot_version, policy_epoch, configuration_epoch,
                    pre_state_digest, resource_claim_digest, revoked, observed_at_ms
             FROM currentness WHERE currentness_key=?1",
            [key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite)?
        .map(|row| decode_currentness(key, row))
        .transpose()
}

fn decode_currentness(
    key: &str,
    row: (i64, i64, i64, String, String, i64, i64),
) -> Result<CurrentnessSnapshot, StoreError> {
    Ok(CurrentnessSnapshot {
        key: key.to_owned(),
        version: decode_u64(row.0)?,
        policy_epoch: decode_u64(row.1)?,
        configuration_epoch: decode_u64(row.2)?,
        pre_state_digest: Digest32::parse(row.3)?,
        resource_claim_digest: Digest32::parse(row.4)?,
        revoked: match row.5 {
            0 => false,
            1 => true,
            _ => return Err(StoreError::Corrupt),
        },
        observed_at_ms: decode_u64(row.6)?,
    })
}

fn load_raw_chain_by_id(
    transaction: &Transaction<'_>,
    grant_id: &str,
) -> Result<Option<RawChain>, StoreError> {
    transaction
        .query_row(
            "SELECT grant_hash, proposal_hash, decision_hash, commitment_json,
                    proposal_json, decision_json, grant_json
             FROM authorization_chains WHERE grant_id=?1",
            [grant_id],
            raw_chain_from_row,
        )
        .optional()
        .map_err(map_sqlite)
}

fn raw_chain_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawChain> {
    Ok(RawChain {
        grant_hash: row.get(0)?,
        proposal_hash: row.get(1)?,
        decision_hash: row.get(2)?,
        commitment_json: row.get(3)?,
        proposal_json: row.get(4)?,
        decision_json: row.get(5)?,
        grant_json: row.get(6)?,
    })
}

fn decode_chain(raw: RawChain) -> Result<StoredChain, StoreError> {
    let commitment = parse_record(&raw.commitment_json)?;
    let proposal = parse_record(&raw.proposal_json)?;
    let decision = parse_record(&raw.decision_json)?;
    let grant = parse_record(&raw.grant_json)?;
    let grant_hash = Digest32::parse(raw.grant_hash)?;
    let verified = verify_grant(&commitment, &proposal, &decision, &grant)?;
    if verified != grant_hash
        || proposal.commitment()?.as_str() != raw.proposal_hash
        || decision.commitment()?.as_str() != raw.decision_hash
    {
        return Err(StoreError::Corrupt);
    }
    Ok(StoredChain {
        grant_hash,
        commitment,
        proposal,
        decision,
        grant,
    })
}

fn load_chain_by_grant_id(
    transaction: &Transaction<'_>,
    grant_id: &str,
) -> Result<Option<StoredChain>, StoreError> {
    load_raw_chain_by_id(transaction, grant_id)?
        .map(decode_chain)
        .transpose()
}

fn load_chain_by_grant_hash(
    transaction: &Transaction<'_>,
    hash: &str,
) -> Result<Option<StoredChain>, StoreError> {
    transaction
        .query_row(
            "SELECT grant_hash, proposal_hash, decision_hash, commitment_json,
                    proposal_json, decision_json, grant_json
             FROM authorization_chains WHERE grant_hash=?1",
            [hash],
            raw_chain_from_row,
        )
        .optional()
        .map_err(map_sqlite)?
        .map(decode_chain)
        .transpose()
}

fn load_chain_by_grant_hash_connection(
    connection: &Connection,
    hash: &str,
) -> Result<Option<StoredChain>, StoreError> {
    connection
        .query_row(
            "SELECT grant_hash, proposal_hash, decision_hash, commitment_json,
                    proposal_json, decision_json, grant_json
             FROM authorization_chains WHERE grant_hash=?1",
            [hash],
            raw_chain_from_row,
        )
        .optional()
        .map_err(map_sqlite)?
        .map(decode_chain)
        .transpose()
}

fn exists(transaction: &Transaction<'_>, column: &str, value: &str) -> Result<bool, StoreError> {
    let sql = match column {
        "proposal_hash" => "SELECT 1 FROM authorization_chains WHERE proposal_hash=?1",
        "decision_hash" => "SELECT 1 FROM authorization_chains WHERE decision_hash=?1",
        _ => return Err(StoreError::InvalidInput("lookup column")),
    };
    transaction
        .query_row(sql, [value], |_| Ok(()))
        .optional()
        .map(|value| value.is_some())
        .map_err(map_sqlite)
}

fn claim_exists(transaction: &Transaction<'_>, hash: &str) -> Result<bool, StoreError> {
    transaction
        .query_row("SELECT 1 FROM claims WHERE grant_hash=?1", [hash], |_| {
            Ok(())
        })
        .optional()
        .map(|value| value.is_some())
        .map_err(map_sqlite)
}

fn load_claim(
    transaction: &Transaction<'_>,
    hash: &str,
) -> Result<Option<DurableClaim>, StoreError> {
    load_claim_impl(transaction, hash)
}

fn load_claim_connection(
    connection: &Connection,
    hash: &str,
) -> Result<Option<DurableClaim>, StoreError> {
    load_claim_impl(connection, hash)
}

fn load_claim_impl(
    connection: &Connection,
    hash: &str,
) -> Result<Option<DurableClaim>, StoreError> {
    connection
        .query_row(
            "SELECT attempt_id, currentness_key, snapshot_version,
                    maximum_snapshot_age_ms, claimed_at_ms, dispatch_started_at_ms
             FROM claims WHERE grant_hash=?1",
            [hash],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite)?
        .map(|row| {
            Ok(DurableClaim {
                grant_hash: Digest32::parse(hash)?,
                attempt_id: row.0,
                currentness_key: row.1,
                snapshot_version: decode_u64(row.2)?,
                maximum_snapshot_age_ms: decode_u64(row.3)?,
                claimed_at_ms: decode_u64(row.4)?,
                dispatch_started_at_ms: row.5.map(decode_u64).transpose()?,
            })
        })
        .transpose()
}

fn validate_dispatch_evidence(
    receipt: &EffectReceipt,
    dispatch_marker: Option<u64>,
) -> Result<(), StoreError> {
    match (receipt.outcome, dispatch_marker, receipt.dispatched_at_ms) {
        (ReceiptOutcome::NotDispatched | ReceiptOutcome::Unknown, None, None) => Ok(()),
        (
            ReceiptOutcome::Succeeded | ReceiptOutcome::Failed | ReceiptOutcome::Unknown,
            Some(marker_time),
            Some(reported),
        ) if marker_time == reported => Ok(()),
        _ => Err(StoreError::DispatchEvidenceMismatch),
    }
}

fn load_receipt_by_grant(
    transaction: &Transaction<'_>,
    hash: &str,
) -> Result<Option<EffectReceipt>, StoreError> {
    load_receipt_by_grant_impl(transaction, hash)
}

fn load_receipt_by_grant_connection(
    connection: &Connection,
    hash: &str,
) -> Result<Option<EffectReceipt>, StoreError> {
    load_receipt_by_grant_impl(connection, hash)
}

fn load_receipt_by_grant_impl(
    connection: &Connection,
    hash: &str,
) -> Result<Option<EffectReceipt>, StoreError> {
    connection
        .query_row(
            "SELECT receipt_hash, receipt_json FROM receipts WHERE grant_hash=?1",
            [hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(map_sqlite)?
        .map(|(stored_hash, bytes)| decode_receipt(&stored_hash, &bytes))
        .transpose()
}

fn load_receipt_by_hash(
    transaction: &Transaction<'_>,
    hash: &str,
) -> Result<Option<EffectReceipt>, StoreError> {
    transaction
        .query_row(
            "SELECT receipt_hash, receipt_json FROM receipts WHERE receipt_hash=?1",
            [hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(map_sqlite)?
        .map(|(stored_hash, bytes)| decode_receipt(&stored_hash, &bytes))
        .transpose()
}

fn decode_receipt(stored_hash: &str, bytes: &[u8]) -> Result<EffectReceipt, StoreError> {
    let receipt: EffectReceipt = parse_record(bytes)?;
    if receipt.commitment()?.as_str() != stored_hash {
        return Err(StoreError::Corrupt);
    }
    Ok(receipt)
}

fn load_reconciliation_at(
    transaction: &Transaction<'_>,
    receipt_hash: &str,
    sequence: u64,
) -> Result<Option<ReconciliationRecord>, StoreError> {
    let sequence = safe_i64(sequence, "reconciliation sequence")?;
    transaction
        .query_row(
            "SELECT record_json FROM reconciliations WHERE receipt_hash=?1 AND sequence=?2",
            params![receipt_hash, sequence],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(map_sqlite)?
        .map(|bytes| parse_record(&bytes).map_err(StoreError::from))
        .transpose()
}

fn load_latest_reconciliation(
    transaction: &Transaction<'_>,
    receipt_hash: &str,
) -> Result<Option<ReconciliationRecord>, StoreError> {
    transaction
        .query_row(
            "SELECT record_json FROM reconciliations WHERE receipt_hash=?1
             ORDER BY sequence DESC LIMIT 1",
            [receipt_hash],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(map_sqlite)?
        .map(|bytes| parse_record(&bytes).map_err(StoreError::from))
        .transpose()
}

fn reconciliation_count(transaction: &Transaction<'_>, hash: &str) -> Result<usize, StoreError> {
    let value = transaction
        .query_row(
            "SELECT COUNT(*) FROM reconciliations WHERE receipt_hash=?1",
            [hash],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sqlite)?;
    usize::try_from(value).map_err(|_| StoreError::Corrupt)
}

fn reconciliation_id_exists(
    transaction: &Transaction<'_>,
    identifier: &str,
) -> Result<bool, StoreError> {
    transaction
        .query_row(
            "SELECT 1 FROM reconciliations WHERE reconciliation_id=?1",
            [identifier],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(map_sqlite)
}

fn load_all_reconciliations(
    connection: &Connection,
    receipt_hash: &str,
) -> Result<Vec<ReconciliationRecord>, StoreError> {
    let mut statement = connection
        .prepare("SELECT record_json FROM reconciliations WHERE receipt_hash=?1 ORDER BY sequence")
        .map_err(map_sqlite)?;
    let rows = statement
        .query_map([receipt_hash], |row| row.get::<_, Vec<u8>>(0))
        .map_err(map_sqlite)?;
    let mut records = Vec::new();
    for row in rows {
        let bytes = row.map_err(map_sqlite)?;
        records.push(parse_record(&bytes)?);
    }
    Ok(records)
}

fn decode_u64(value: i64) -> Result<u64, StoreError> {
    let value = u64::try_from(value).map_err(|_| StoreError::Corrupt)?;
    if value > MAX_SAFE_INTEGER {
        return Err(StoreError::Corrupt);
    }
    Ok(value)
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation
    )
}

fn map_sqlite(error: rusqlite::Error) -> StoreError {
    let corrupt = matches!(
        &error,
        rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
            | rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::QueryReturnedMoreThanOneRow
    );
    drop(error);
    if corrupt {
        StoreError::Corrupt
    } else {
        StoreError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use effect_transaction_core::{DecisionOutcome, ReconciliationOutcome};

    #[derive(Clone)]
    struct Fixture {
        commitment: TaskCommitment,
        proposal: EffectProposal,
        decision: AuthorizationDecision,
        grant: ExecutionGrant,
    }

    fn digest(label: &str) -> Digest32 {
        Digest32::from_payload(label.as_bytes())
    }

    fn fixture(suffix: &str) -> Result<Fixture, ProtocolError> {
        let commitment = TaskCommitment {
            version: 1,
            commitment_id: format!("task-{suffix}"),
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
            proposal_id: format!("proposal-{suffix}"),
            commitment_hash: commitment.commitment()?,
            effect_profile: "mcp/tool-call@1".into(),
            operation: "filesystem.write".into(),
            target: format!("workspace:/{suffix}.md"),
            arguments_digest: digest("arguments"),
            expected_effect_digest: digest("expected"),
            pre_state_digest: digest("pre-state"),
            resource_claim_digest: digest("resources"),
            created_at_ms: 2_000,
            expires_at_ms: 15_000,
        };
        let decision = AuthorizationDecision {
            version: 1,
            decision_id: format!("decision-{suffix}"),
            proposal_hash: proposal.commitment()?,
            evidence_hashes: vec![digest("evidence")],
            outcome: DecisionOutcome::Allow,
            reason_codes: vec!["policy_allow".into()],
            decided_at_ms: 3_000,
            expires_at_ms: 10_000,
        };
        let grant = ExecutionGrant {
            version: 1,
            grant_id: format!("grant-{suffix}"),
            proposal_hash: proposal.commitment()?,
            decision_hash: decision.commitment()?,
            audience: "runner:prod".into(),
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
        })
    }

    fn snapshot(version: u64) -> CurrentnessSnapshot {
        CurrentnessSnapshot {
            key: "cluster/prod/deployment/api".into(),
            version,
            policy_epoch: 7,
            configuration_epoch: 3,
            pre_state_digest: digest("pre-state"),
            resource_claim_digest: digest("resources"),
            revoked: false,
            observed_at_ms: 3_900 + version,
        }
    }

    fn request(attempt: &str, version: u64) -> ClaimRequest {
        ClaimRequest {
            attempt_id: attempt.into(),
            expected_audience: "runner:prod".into(),
            currentness_key: "cluster/prod/deployment/api".into(),
            expected_snapshot_version: version,
            maximum_snapshot_age_ms: 5_000,
        }
    }

    fn register(store: &mut SqliteEffectStore, fixture: &Fixture) -> Result<Digest32, StoreError> {
        store.register_chain(
            &fixture.commitment,
            &fixture.proposal,
            &fixture.decision,
            &fixture.grant,
        )
    }

    #[test]
    fn full_lifecycle_survives_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("etp.sqlite3");
        let data = fixture("one")?;
        let grant_hash;
        let receipt_hash;
        {
            let mut store = SqliteEffectStore::open(&path)?;
            grant_hash = register(&mut store, &data)?;
            assert_eq!(register(&mut store, &data)?, grant_hash);
            store.put_currentness(&snapshot(1))?;
            let claim = store.claim(&data.grant, &request("attempt-one", 1), 4_000)?;
            assert_eq!(claim.grant_hash, grant_hash);
            store.mark_dispatch_started(&grant_hash, "attempt-one", 4_100)?;
            let receipt = EffectReceipt {
                version: 1,
                receipt_id: "receipt-one".into(),
                proposal_hash: data.proposal.commitment()?,
                grant_hash: grant_hash.clone(),
                attempt_id: "attempt-one".into(),
                claimed_at_ms: 4_000,
                dispatched_at_ms: Some(4_100),
                completed_at_ms: 4_500,
                outcome: ReceiptOutcome::Unknown,
                observation_digest: digest("unknown"),
            };
            receipt_hash = store.record_receipt(&receipt)?;
            let reconciliation = ReconciliationRecord {
                version: 1,
                reconciliation_id: "reconcile-one".into(),
                receipt_hash: receipt_hash.clone(),
                sequence: 1,
                parent_reconciliation_hash: None,
                observed_at_ms: 5_000,
                outcome: ReconciliationOutcome::EffectConfirmed,
                evidence_digest: digest("target-observation"),
            };
            store.append_reconciliation(&reconciliation)?;
        }
        let reopened = SqliteEffectStore::open(&path)?;
        let lifecycle = reopened.lifecycle(&grant_hash)?;
        assert_eq!(
            lifecycle
                .claim
                .as_ref()
                .map(|value| value.attempt_id.as_str()),
            Some("attempt-one")
        );
        assert_eq!(
            lifecycle
                .receipt
                .as_ref()
                .map(|value| value.receipt_id.as_str()),
            Some("receipt-one")
        );
        assert_eq!(lifecycle.reconciliations.len(), 1);
        assert_eq!(lifecycle.reconciliations[0].receipt_hash, receipt_hash);
        Ok(())
    }

    #[test]
    fn stale_currentness_rolls_back_claim_atomically() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let mut store = SqliteEffectStore::open(root.path().join("atomic.sqlite3"))?;
        let data = fixture("atomic")?;
        let hash = register(&mut store, &data)?;
        store.put_currentness(&snapshot(2))?;
        assert!(matches!(
            store.claim(&data.grant, &request("losing-attempt", 1), 4_000),
            Err(StoreError::StaleSnapshot)
        ));
        assert!(store.lifecycle(&hash)?.claim.is_none());
        let winning = store.claim(&data.grant, &request("winning-attempt", 2), 4_001)?;
        assert_eq!(winning.attempt_id, "winning-attempt");
        Ok(())
    }

    #[test]
    fn claim_rejects_stale_and_future_currentness_without_consuming_grant()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let mut store = SqliteEffectStore::open(root.path().join("freshness.sqlite3"))?;
        let data = fixture("freshness")?;
        let hash = register(&mut store, &data)?;

        let mut old = snapshot(1);
        old.observed_at_ms = 3_000;
        store.put_currentness(&old)?;
        let mut old_request = request("old-attempt", 1);
        old_request.maximum_snapshot_age_ms = 100;
        assert!(matches!(
            store.claim(&data.grant, &old_request, 4_000),
            Err(StoreError::StaleCurrentness)
        ));
        assert!(store.lifecycle(&hash)?.claim.is_none());

        let mut future = snapshot(2);
        future.observed_at_ms = 4_100;
        store.put_currentness(&future)?;
        assert!(matches!(
            store.claim(&data.grant, &request("future-attempt", 2), 4_000),
            Err(StoreError::SnapshotFromFuture)
        ));
        assert!(store.lifecycle(&hash)?.claim.is_none());
        Ok(())
    }

    #[test]
    fn dispatch_reapplies_the_claimed_freshness_budget() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let mut store = SqliteEffectStore::open(root.path().join("dispatch-freshness.sqlite3"))?;
        let data = fixture("dispatch-freshness")?;
        let hash = register(&mut store, &data)?;
        let mut current = snapshot(1);
        current.observed_at_ms = 3_950;
        store.put_currentness(&current)?;
        let mut claim_request = request("fresh-at-claim", 1);
        claim_request.maximum_snapshot_age_ms = 100;
        store.claim(&data.grant, &claim_request, 4_000)?;

        assert!(matches!(
            store.mark_dispatch_started(&hash, "fresh-at-claim", 4_051),
            Err(StoreError::StaleCurrentness)
        ));
        assert_eq!(
            store
                .lifecycle(&hash)?
                .claim
                .and_then(|claim| claim.dispatch_started_at_ms),
            None
        );
        Ok(())
    }

    #[test]
    fn currentness_is_rechecked_at_the_dispatch_boundary() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let mut store = SqliteEffectStore::open(root.path().join("dispatch-fence.sqlite3"))?;
        let data = fixture("dispatch-fence")?;
        let hash = register(&mut store, &data)?;
        store.put_currentness(&snapshot(1))?;
        store.claim(&data.grant, &request("fenced-attempt", 1), 4_000)?;
        store.put_currentness(&snapshot(2))?;
        assert!(matches!(
            store.mark_dispatch_started(&hash, "fenced-attempt", 4_100),
            Err(StoreError::StaleSnapshot)
        ));
        let lifecycle = store.lifecycle(&hash)?;
        assert_eq!(
            lifecycle
                .claim
                .and_then(|claim| claim.dispatch_started_at_ms),
            None
        );
        Ok(())
    }

    #[test]
    fn two_connections_cannot_claim_the_same_grant() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("concurrent.sqlite3");
        let data = fixture("race")?;
        let mut setup = SqliteEffectStore::open(&path)?;
        register(&mut setup, &data)?;
        setup.put_currentness(&snapshot(1))?;
        drop(setup);

        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for index in 0..2 {
            let path = path.clone();
            let grant = data.grant.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut store = SqliteEffectStore::open(path)?;
                barrier.wait();
                store.claim(&grant, &request(&format!("attempt-{index}"), 1), 4_000)
            }));
        }
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| StoreError::Unavailable))
            .collect::<Result<_, _>>()?;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(StoreError::GrantAlreadyClaimed)))
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn dispatch_and_receipt_evidence_cannot_conflict() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let mut store = SqliteEffectStore::open(root.path().join("dispatch.sqlite3"))?;
        let data = fixture("dispatch")?;
        let hash = register(&mut store, &data)?;
        store.put_currentness(&snapshot(1))?;
        store.claim(&data.grant, &request("attempt-dispatch", 1), 4_000)?;
        store.mark_dispatch_started(&hash, "attempt-dispatch", 4_100)?;
        let contradictory = EffectReceipt {
            version: 1,
            receipt_id: "receipt-not-dispatched".into(),
            proposal_hash: data.proposal.commitment()?,
            grant_hash: hash.clone(),
            attempt_id: "attempt-dispatch".into(),
            claimed_at_ms: 4_000,
            dispatched_at_ms: None,
            completed_at_ms: 4_200,
            outcome: ReceiptOutcome::NotDispatched,
            observation_digest: digest("none"),
        };
        assert!(matches!(
            store.record_receipt(&contradictory),
            Err(StoreError::DispatchEvidenceMismatch)
        ));
        assert!(store.lifecycle(&hash)?.receipt.is_none());
        Ok(())
    }

    #[test]
    fn all_receipt_outcomes_preserve_exact_dispatch_knowledge()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let cases = [
            ("not-dispatched", ReceiptOutcome::NotDispatched, false),
            ("succeeded", ReceiptOutcome::Succeeded, true),
            ("failed", ReceiptOutcome::Failed, true),
            ("unknown", ReceiptOutcome::Unknown, true),
        ];
        for (suffix, outcome, dispatched) in cases {
            let mut store = SqliteEffectStore::open(root.path().join(format!("{suffix}.sqlite3")))?;
            let data = fixture(suffix)?;
            let hash = register(&mut store, &data)?;
            store.put_currentness(&snapshot(1))?;
            let attempt = format!("attempt-{suffix}");
            store.claim(&data.grant, &request(&attempt, 1), 4_000)?;
            let dispatched_at_ms = if dispatched {
                store.mark_dispatch_started(&hash, &attempt, 4_100)?;
                Some(4_100)
            } else {
                None
            };
            let receipt = EffectReceipt {
                version: 1,
                receipt_id: format!("receipt-{suffix}"),
                proposal_hash: data.proposal.commitment()?,
                grant_hash: hash.clone(),
                attempt_id: attempt,
                claimed_at_ms: 4_000,
                dispatched_at_ms,
                completed_at_ms: 4_500,
                outcome,
                observation_digest: digest(suffix),
            };
            store.record_receipt(&receipt)?;
            assert_eq!(store.lifecycle(&hash)?.receipt, Some(receipt));
        }
        Ok(())
    }

    #[test]
    fn trusted_clock_and_attempt_uniqueness_survive_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("durable-authority.sqlite3");
        let first = fixture("first")?;
        let second = fixture("second")?;
        {
            let mut store = SqliteEffectStore::open(&path)?;
            register(&mut store, &first)?;
            register(&mut store, &second)?;
            store.put_currentness(&snapshot(1))?;
            store.claim(&first.grant, &request("global-attempt", 1), 5_000)?;
        }
        let mut reopened = SqliteEffectStore::open(&path)?;
        assert!(matches!(
            reopened.claim(&second.grant, &request("other-attempt", 1), 4_999),
            Err(StoreError::ClockRollback)
        ));
        assert!(matches!(
            reopened.claim(&second.grant, &request("global-attempt", 1), 5_001),
            Err(StoreError::AttemptAlreadyUsed)
        ));
        let second_hash = second.grant.commitment()?;
        assert!(reopened.lifecycle(&second_hash)?.claim.is_none());
        reopened.claim(&second.grant, &request("fresh-attempt", 1), 5_002)?;
        Ok(())
    }

    #[test]
    fn currentness_is_monotonic_and_revocation_is_sticky_per_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let mut store = SqliteEffectStore::open(root.path().join("currentness.sqlite3"))?;
        let mut revoked = snapshot(1);
        revoked.revoked = true;
        store.put_currentness(&revoked)?;
        let mut stale = revoked.clone();
        stale.version = 1;
        stale.revoked = false;
        assert!(matches!(
            store.put_currentness(&stale),
            Err(StoreError::CurrentnessVersionConflict)
        ));
        let mut rollback = revoked.clone();
        rollback.version = 2;
        rollback.revoked = false;
        rollback.observed_at_ms += 1;
        assert!(matches!(
            store.put_currentness(&rollback),
            Err(StoreError::RevocationRollback)
        ));
        rollback.policy_epoch += 1;
        store.put_currentness(&rollback)?;
        Ok(())
    }

    #[test]
    fn unknown_and_foreign_schemas_are_refused_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let future = root.path().join("future.sqlite3");
        let connection = Connection::open(&future)?;
        connection.execute_batch(
            "CREATE TABLE keep(value TEXT); INSERT INTO keep VALUES('x'); PRAGMA user_version=99;",
        )?;
        drop(connection);
        assert!(matches!(
            SqliteEffectStore::open(&future),
            Err(StoreError::IncompatibleSchema)
        ));
        let foreign = root.path().join("foreign.sqlite3");
        let connection = Connection::open(&foreign)?;
        connection.execute("CREATE TABLE keep(value TEXT)", [])?;
        drop(connection);
        assert!(matches!(
            SqliteEffectStore::open(&foreign),
            Err(StoreError::ForeignDatabase)
        ));
        Ok(())
    }
}

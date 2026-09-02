//! COSE Sign1 and Ed25519 authority assertions for ETP records.
//!
//! This crate verifies profile bindings against current authority data from the
//! host. It does not provide PKI, key discovery, a trusted clock, or execution.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use coset::{
    CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use effect_transaction_core::{
    Digest32, ProtocolError, ProtocolRecord, canonical_json, parse_record,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Profile identifier carried by each assertion.
pub const AUTHORITY_PROFILE: &str = "effect-transaction/authority/cose-sign1-ed25519/0.1";
/// Authority-profile record version.
pub const AUTHORITY_PROFILE_VERSION: u64 = 1;
/// Protected COSE content type.
pub const COSE_CONTENT_TYPE: &str = "application/etp-authority+cjson;profile=0.1";
/// Domain in the canonical COSE external additional authenticated data.
pub const SIGNATURE_DOMAIN: &str = "effect-transaction/authority/cose-sign1-ed25519/0.1/signature";
/// Domain for the authority-statement commitment.
pub const AUTHORITY_STATEMENT_DOMAIN: &str =
    "effect-transaction/authority/cose-sign1-ed25519/0.1/statement";
/// Maximum accepted encoded COSE object size.
pub const MAX_COSE_BYTES: usize = 16_384;
/// Maximum accepted canonical authority payload size.
pub const MAX_PAYLOAD_BYTES: usize = 8_192;
/// Maximum assertion validity interval.
pub const MAX_ASSERTION_LIFETIME_MS: u64 = 300_000;
/// Maximum snapshot age a verifier is permitted to configure.
pub const MAX_AUTHORITY_SNAPSHOT_AGE_MS: u64 = 300_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// ETP core record kinds that an assertion can sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    TaskCommitment,
    EffectProposal,
    AuthorizationDecision,
    ExecutionGrant,
    EffectReceipt,
    ReconciliationRecord,
}

/// Canonical payload embedded in `COSE_Sign1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityStatement {
    pub version: u64,
    pub authority_profile: String,
    pub statement_id: String,
    pub issuer: String,
    pub key_id: String,
    pub role: String,
    pub audience: String,
    pub record_profile: String,
    pub record_version: u64,
    pub record_kind: RecordKind,
    pub record_digest: Digest32,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub authority_epoch: u64,
    pub configuration_epoch: u64,
}

impl AuthorityStatement {
    /// Validates the statement against the authority profile.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported profile, invalid binding, out-of-range
    /// integer, or invalid validity interval.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        if self.version != AUTHORITY_PROFILE_VERSION || self.authority_profile != AUTHORITY_PROFILE
        {
            return Err(AuthorityError::UnsupportedAuthorityProfile);
        }
        validate_opaque("statement_id", &self.statement_id, 256)?;
        validate_opaque("issuer", &self.issuer, 512)?;
        validate_opaque("key_id", &self.key_id, 256)?;
        validate_token("role", &self.role)?;
        validate_token("record_profile", &self.record_profile)?;
        validate_opaque("audience", &self.audience, 512)?;
        if self.record_version == 0 {
            return Err(AuthorityError::InvalidField("record_version"));
        }
        for (field, value) in [
            ("version", self.version),
            ("record_version", self.record_version),
            ("issued_at_ms", self.issued_at_ms),
            ("not_before_ms", self.not_before_ms),
            ("expires_at_ms", self.expires_at_ms),
            ("authority_epoch", self.authority_epoch),
            ("configuration_epoch", self.configuration_epoch),
        ] {
            validate_safe_integer(field, value)?;
        }
        if self.issued_at_ms > self.not_before_ms
            || self.not_before_ms >= self.expires_at_ms
            || self.expires_at_ms - self.not_before_ms > MAX_ASSERTION_LIFETIME_MS
        {
            return Err(AuthorityError::InvalidValidityInterval);
        }
        Ok(())
    }
}

impl ProtocolRecord for AuthorityStatement {
    const DOMAIN: &'static str = AUTHORITY_STATEMENT_DOMAIN;

    fn validate(&self) -> Result<(), ProtocolError> {
        AuthorityStatement::validate(self)
            .map_err(|_| ProtocolError::InvalidBinding("authority_statement"))
    }
}

/// Current trust and revocation data supplied by the host.
///
/// This value does not authenticate itself. The caller must obtain it from a
/// trusted configuration and revocation source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub issuer: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub authorized_roles: BTreeSet<String>,
    pub authorized_audiences: BTreeSet<String>,
    pub authority_epoch: u64,
    pub configuration_epoch: u64,
    pub key_valid_from_ms: u64,
    pub key_valid_until_ms: u64,
    pub revoked_at_ms: Option<u64>,
    pub observed_at_ms: u64,
}

impl AuthoritySnapshot {
    /// Validates an authority snapshot supplied by the host.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata or an invalid Ed25519 key.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        validate_opaque("issuer", &self.issuer, 512)?;
        validate_opaque("key_id", &self.key_id, 256)?;
        if self.authorized_roles.is_empty() || self.authorized_audiences.is_empty() {
            return Err(AuthorityError::EmptyAuthorizationSet);
        }
        for role in &self.authorized_roles {
            validate_token("authorized_role", role)?;
        }
        for audience in &self.authorized_audiences {
            validate_opaque("authorized_audience", audience, 512)?;
        }
        for (field, value) in [
            ("authority_epoch", self.authority_epoch),
            ("configuration_epoch", self.configuration_epoch),
            ("key_valid_from_ms", self.key_valid_from_ms),
            ("key_valid_until_ms", self.key_valid_until_ms),
            ("observed_at_ms", self.observed_at_ms),
        ] {
            validate_safe_integer(field, value)?;
        }
        if let Some(revoked_at_ms) = self.revoked_at_ms {
            validate_safe_integer("revoked_at_ms", revoked_at_ms)?;
        }
        if self.key_valid_from_ms >= self.key_valid_until_ms {
            return Err(AuthorityError::InvalidKeyValidityInterval);
        }
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| AuthorityError::InvalidPublicKey)?;
        if key.is_weak() {
            return Err(AuthorityError::InvalidPublicKey);
        }
        Ok(())
    }
}

/// Expected record and authority bindings for verification.
#[derive(Clone, Copy, Debug)]
pub struct VerificationContext<'a> {
    pub expected_record_profile: &'a str,
    pub expected_record_version: u64,
    pub expected_record_kind: RecordKind,
    pub expected_record_digest: &'a Digest32,
    pub expected_role: &'a str,
    pub expected_audience: &'a str,
    pub now_ms: u64,
    pub maximum_snapshot_age_ms: u64,
}

impl VerificationContext<'_> {
    fn validate(&self) -> Result<(), AuthorityError> {
        validate_token("expected_record_profile", self.expected_record_profile)?;
        validate_token("expected_role", self.expected_role)?;
        validate_opaque("expected_audience", self.expected_audience, 512)?;
        validate_safe_integer("expected_record_version", self.expected_record_version)?;
        validate_safe_integer("now_ms", self.now_ms)?;
        validate_safe_integer("maximum_snapshot_age_ms", self.maximum_snapshot_age_ms)?;
        if self.expected_record_version == 0 {
            return Err(AuthorityError::InvalidField("expected_record_version"));
        }
        if self.maximum_snapshot_age_ms > MAX_AUTHORITY_SNAPSHOT_AGE_MS {
            return Err(AuthorityError::SnapshotAgePolicyTooPermissive);
        }
        Ok(())
    }
}

/// An authority assertion that passed all verification checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAuthority {
    statement: AuthorityStatement,
    verified_at_ms: u64,
    snapshot_observed_at_ms: u64,
    verifying_key_digest: Digest32,
}

impl VerifiedAuthority {
    #[must_use]
    pub fn statement(&self) -> &AuthorityStatement {
        &self.statement
    }

    #[must_use]
    pub const fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }

    #[must_use]
    pub const fn snapshot_observed_at_ms(&self) -> u64 {
        self.snapshot_observed_at_ms
    }

    #[must_use]
    pub fn verifying_key_digest(&self) -> &Digest32 {
        &self.verifying_key_digest
    }
}

/// Ed25519 signing identity for the reference profile.
///
/// Production deployments should keep private keys in a signing service or a
/// hardware-backed key store.
#[derive(Debug)]
pub struct SigningAuthority {
    issuer: String,
    key_id: String,
    key: SigningKey,
}

impl SigningAuthority {
    /// Imports a 32-byte Ed25519 seed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity metadata or an invalid public key.
    pub fn from_seed(
        issuer: impl Into<String>,
        key_id: impl Into<String>,
        seed: [u8; 32],
    ) -> Result<Self, AuthorityError> {
        let issuer = issuer.into();
        let key_id = key_id.into();
        validate_opaque("issuer", &issuer, 512)?;
        validate_opaque("key_id", &key_id, 256)?;
        let key = SigningKey::from_bytes(&seed);
        if key.verifying_key().is_weak() {
            return Err(AuthorityError::InvalidPublicKey);
        }
        Ok(Self {
            issuer,
            key_id,
            key,
        })
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Creates a deterministic `COSE_Sign1` object.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid statement, identity mismatch, or encoding
    /// failure.
    pub fn sign(&self, statement: &AuthorityStatement) -> Result<Vec<u8>, AuthorityError> {
        statement.validate()?;
        if statement.issuer != self.issuer {
            return Err(AuthorityError::IssuerMismatch);
        }
        if statement.key_id != self.key_id {
            return Err(AuthorityError::KeyIdMismatch);
        }
        let payload = canonical_json(statement).map_err(AuthorityError::Protocol)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AuthorityError::PayloadTooLarge);
        }
        let protected = expected_header(&self.key_id);
        let external_aad = authority_external_aad(statement)?;
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(&external_aad, |to_be_signed| {
                self.key.sign(to_be_signed).to_bytes().to_vec()
            })
            .build();
        let encoded = cose
            .to_tagged_vec()
            .map_err(|error| AuthorityError::MalformedCose(error.to_string()))?;
        if encoded.len() > MAX_COSE_BYTES {
            return Err(AuthorityError::CoseTooLarge);
        }
        Ok(encoded)
    }
}

/// Verifies one ETP authority assertion against current host authority data.
///
/// # Errors
///
/// Returns an error for an encoding, signature, identity, role, audience,
/// record, time, epoch, currentness, key-validity, or revocation failure.
pub fn verify_authority(
    encoded: &[u8],
    snapshot: &AuthoritySnapshot,
    context: VerificationContext<'_>,
) -> Result<VerifiedAuthority, AuthorityError> {
    context.validate()?;
    snapshot.validate()?;
    if encoded.len() > MAX_COSE_BYTES {
        return Err(AuthorityError::CoseTooLarge);
    }

    let signed = CoseSign1::from_tagged_slice(encoded)
        .map_err(|e| AuthorityError::MalformedCose(e.to_string()))?;
    let canonical_cose = signed
        .clone()
        .to_tagged_vec()
        .map_err(|e| AuthorityError::MalformedCose(e.to_string()))?;
    if canonical_cose != encoded {
        return Err(AuthorityError::NonCanonicalCose);
    }
    if !signed.unprotected.is_empty() {
        return Err(AuthorityError::UnprotectedHeaders);
    }
    let payload = signed
        .payload
        .as_ref()
        .ok_or(AuthorityError::MissingPayload)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AuthorityError::PayloadTooLarge);
    }
    let statement: AuthorityStatement = parse_record(payload).map_err(AuthorityError::Protocol)?;
    statement.validate()?;
    let canonical_payload = canonical_json(&statement).map_err(AuthorityError::Protocol)?;
    if canonical_payload != *payload {
        return Err(AuthorityError::NonCanonicalPayload);
    }

    let protected = expected_header(&statement.key_id);
    if signed.protected.header != protected {
        return Err(AuthorityError::InvalidProtectedHeaders);
    }
    let protected_bytes = protected
        .to_vec()
        .map_err(|e| AuthorityError::MalformedCose(e.to_string()))?;
    if signed.protected.original_data.as_deref() != Some(protected_bytes.as_slice()) {
        return Err(AuthorityError::NonCanonicalCose);
    }

    if statement.issuer != snapshot.issuer {
        return Err(AuthorityError::IssuerMismatch);
    }
    if statement.key_id != snapshot.key_id {
        return Err(AuthorityError::KeyIdMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&snapshot.public_key)
        .map_err(|_| AuthorityError::InvalidPublicKey)?;
    let external_aad = authority_external_aad(&statement)?;
    signed
        .verify_signature(&external_aad, |signature, to_be_signed| {
            let signature =
                Signature::from_slice(signature).map_err(|_| AuthorityError::InvalidSignature)?;
            verifying_key
                .verify_strict(to_be_signed, &signature)
                .map_err(|_| AuthorityError::InvalidSignature)
        })
        .map_err(|_| AuthorityError::InvalidSignature)?;

    verify_bindings(&statement, snapshot, context)?;

    Ok(VerifiedAuthority {
        statement,
        verified_at_ms: context.now_ms,
        snapshot_observed_at_ms: snapshot.observed_at_ms,
        verifying_key_digest: Digest32::from_payload(&snapshot.public_key),
    })
}

fn verify_bindings(
    statement: &AuthorityStatement,
    snapshot: &AuthoritySnapshot,
    context: VerificationContext<'_>,
) -> Result<(), AuthorityError> {
    if snapshot.observed_at_ms > context.now_ms {
        return Err(AuthorityError::SnapshotFromFuture);
    }
    if context.now_ms - snapshot.observed_at_ms > context.maximum_snapshot_age_ms {
        return Err(AuthorityError::StaleSnapshot);
    }
    if snapshot.observed_at_ms < statement.issued_at_ms {
        return Err(AuthorityError::SnapshotPredatesStatement);
    }
    if context.now_ms < statement.not_before_ms {
        return Err(AuthorityError::AssertionNotYetValid);
    }
    if context.now_ms >= statement.expires_at_ms {
        return Err(AuthorityError::AssertionExpired);
    }
    if context.now_ms < snapshot.key_valid_from_ms {
        return Err(AuthorityError::KeyNotYetValid);
    }
    if context.now_ms >= snapshot.key_valid_until_ms {
        return Err(AuthorityError::KeyExpired);
    }
    if statement.issued_at_ms < snapshot.key_valid_from_ms
        || statement.issued_at_ms >= snapshot.key_valid_until_ms
    {
        return Err(AuthorityError::KeyNotValidAtIssuance);
    }
    if snapshot
        .revoked_at_ms
        .is_some_and(|revoked_at_ms| revoked_at_ms <= context.now_ms)
    {
        return Err(AuthorityError::KeyRevoked);
    }
    if statement.authority_epoch != snapshot.authority_epoch {
        return Err(AuthorityError::AuthorityEpochMismatch);
    }
    if statement.configuration_epoch != snapshot.configuration_epoch {
        return Err(AuthorityError::ConfigurationEpochMismatch);
    }
    if statement.role != context.expected_role {
        return Err(AuthorityError::RoleMismatch);
    }
    if !snapshot.authorized_roles.contains(&statement.role) {
        return Err(AuthorityError::RoleNotAuthorized);
    }
    if statement.audience != context.expected_audience {
        return Err(AuthorityError::AudienceMismatch);
    }
    if !snapshot.authorized_audiences.contains(&statement.audience) {
        return Err(AuthorityError::AudienceNotAuthorized);
    }
    if statement.record_profile != context.expected_record_profile {
        return Err(AuthorityError::RecordProfileMismatch);
    }
    if statement.record_version != context.expected_record_version {
        return Err(AuthorityError::RecordVersionMismatch);
    }
    if statement.record_kind != context.expected_record_kind {
        return Err(AuthorityError::RecordKindMismatch);
    }
    if &statement.record_digest != context.expected_record_digest {
        return Err(AuthorityError::RecordDigestMismatch);
    }
    Ok(())
}

#[derive(Serialize)]
struct ExternalAad<'a> {
    domain: &'static str,
    authority_profile: &'a str,
    authority_profile_version: u64,
    record_profile: &'a str,
    record_version: u64,
    record_kind: RecordKind,
}

/// Returns the external additional authenticated data used in the COSE
/// `Sig_structure`.
///
/// Independent implementations can use these bytes to verify interoperability.
///
/// # Errors
///
/// Returns an error if canonical ETP JSON encoding fails.
pub fn authority_external_aad(statement: &AuthorityStatement) -> Result<Vec<u8>, AuthorityError> {
    canonical_json(&ExternalAad {
        domain: SIGNATURE_DOMAIN,
        authority_profile: &statement.authority_profile,
        authority_profile_version: statement.version,
        record_profile: &statement.record_profile,
        record_version: statement.record_version,
        record_kind: statement.record_kind,
    })
    .map_err(AuthorityError::Protocol)
}

fn expected_header(key_id: &str) -> coset::Header {
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(key_id.as_bytes().to_vec())
        .content_type(COSE_CONTENT_TYPE.to_owned())
        .build()
}

fn validate_safe_integer(field: &'static str, value: u64) -> Result<(), AuthorityError> {
    if value > MAX_SAFE_INTEGER {
        Err(AuthorityError::UnsafeInteger(field))
    } else {
        Ok(())
    }
}

fn validate_opaque(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), AuthorityError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(AuthorityError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_token(field: &'static str, value: &str) -> Result<(), AuthorityError> {
    validate_opaque(field, value, 256)?;
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(b'a'..=b'z'))
        || !bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'/' | b'-'
            )
        })
    {
        return Err(AuthorityError::InvalidField(field));
    }
    Ok(())
}

/// Errors returned by the ETP authority profile.
#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("unsupported ETP authority profile or version")]
    UnsupportedAuthorityProfile,
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("integer exceeds the interoperable JSON range: {0}")]
    UnsafeInteger(&'static str),
    #[error("invalid assertion validity interval")]
    InvalidValidityInterval,
    #[error("invalid authority-key validity interval")]
    InvalidKeyValidityInterval,
    #[error("authority snapshot has no roles or audiences")]
    EmptyAuthorizationSet,
    #[error("invalid or weak Ed25519 public key")]
    InvalidPublicKey,
    #[error("COSE object exceeds the profile size limit")]
    CoseTooLarge,
    #[error("authority payload exceeds the profile size limit")]
    PayloadTooLarge,
    #[error("malformed COSE object: {0}")]
    MalformedCose(String),
    #[error("COSE object is not deterministic CBOR")]
    NonCanonicalCose,
    #[error("COSE protected headers do not match the authority profile")]
    InvalidProtectedHeaders,
    #[error("COSE unprotected headers are forbidden")]
    UnprotectedHeaders,
    #[error("COSE object has no embedded payload")]
    MissingPayload,
    #[error("authority payload is not canonical ETP JSON")]
    NonCanonicalPayload,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
    #[error("authority issuer mismatch")]
    IssuerMismatch,
    #[error("authority key identifier mismatch")]
    KeyIdMismatch,
    #[error("authority role does not match the required role")]
    RoleMismatch,
    #[error("signing key is not authorized for this role")]
    RoleNotAuthorized,
    #[error("authority audience does not match the executor audience")]
    AudienceMismatch,
    #[error("signing key is not authorized for this audience")]
    AudienceNotAuthorized,
    #[error("record profile mismatch")]
    RecordProfileMismatch,
    #[error("record version mismatch")]
    RecordVersionMismatch,
    #[error("record kind mismatch")]
    RecordKindMismatch,
    #[error("record digest mismatch")]
    RecordDigestMismatch,
    #[error("authority snapshot is from the future")]
    SnapshotFromFuture,
    #[error("authority snapshot predates the assertion")]
    SnapshotPredatesStatement,
    #[error("authority snapshot is stale")]
    StaleSnapshot,
    #[error("snapshot age policy exceeds the profile maximum")]
    SnapshotAgePolicyTooPermissive,
    #[error("authority assertion is not yet valid")]
    AssertionNotYetValid,
    #[error("authority assertion expired")]
    AssertionExpired,
    #[error("authority key is not yet valid")]
    KeyNotYetValid,
    #[error("authority key expired")]
    KeyExpired,
    #[error("authority key was not valid when the assertion was issued")]
    KeyNotValidAtIssuance,
    #[error("authority key is revoked")]
    KeyRevoked,
    #[error("authority epoch mismatch")]
    AuthorityEpochMismatch,
    #[error("configuration epoch mismatch")]
    ConfigurationEpochMismatch,
    #[error("ETP record validation failed: {0}")]
    Protocol(#[source] effect_transaction_core::ProtocolError),
}

impl AuthorityError {
    /// Returns the stable error code used by conformance tests and host
    /// integrations.
    ///
    /// The display text is not part of the protocol.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedAuthorityProfile => "unsupported_authority_profile",
            Self::InvalidField(_) => "invalid_field",
            Self::UnsafeInteger(_) => "unsafe_integer",
            Self::InvalidValidityInterval => "invalid_validity_interval",
            Self::InvalidKeyValidityInterval => "invalid_key_validity_interval",
            Self::EmptyAuthorizationSet => "empty_authorization_set",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::CoseTooLarge => "cose_too_large",
            Self::PayloadTooLarge => "payload_too_large",
            Self::MalformedCose(_) => "malformed_cose",
            Self::NonCanonicalCose => "noncanonical_cose",
            Self::InvalidProtectedHeaders => "invalid_protected_headers",
            Self::UnprotectedHeaders => "unprotected_headers",
            Self::MissingPayload => "missing_payload",
            Self::NonCanonicalPayload => "noncanonical_payload",
            Self::InvalidSignature => "invalid_signature",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::KeyIdMismatch => "key_id_mismatch",
            Self::RoleMismatch => "role_mismatch",
            Self::RoleNotAuthorized => "role_not_authorized",
            Self::AudienceMismatch => "audience_mismatch",
            Self::AudienceNotAuthorized => "audience_not_authorized",
            Self::RecordProfileMismatch => "record_profile_mismatch",
            Self::RecordVersionMismatch => "record_version_mismatch",
            Self::RecordKindMismatch => "record_kind_mismatch",
            Self::RecordDigestMismatch => "record_digest_mismatch",
            Self::SnapshotFromFuture => "snapshot_from_future",
            Self::SnapshotPredatesStatement => "snapshot_predates_statement",
            Self::StaleSnapshot => "stale_snapshot",
            Self::SnapshotAgePolicyTooPermissive => "snapshot_age_policy_too_permissive",
            Self::AssertionNotYetValid => "assertion_not_yet_valid",
            Self::AssertionExpired => "assertion_expired",
            Self::KeyNotYetValid => "key_not_yet_valid",
            Self::KeyExpired => "key_expired",
            Self::KeyNotValidAtIssuance => "key_not_valid_at_issuance",
            Self::KeyRevoked => "key_revoked",
            Self::AuthorityEpochMismatch => "authority_epoch_mismatch",
            Self::ConfigurationEpochMismatch => "configuration_epoch_mismatch",
            Self::Protocol(_) => "protocol_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, RngSeed, TestCaseError};

    use super::*;

    const NOW: u64 = 1_000_100;
    const AUTHORITY_VECTOR: &[u8] =
        include_bytes!("../test-vectors/authority-cose-sign1-ed25519-0.1.json");

    #[derive(Debug, Deserialize)]
    struct PublishedAuthorityVector {
        profile: String,
        description: String,
        seed_hex: String,
        public_key_hex: String,
        statement: AuthorityStatement,
        protected_header_hex: String,
        payload_hex: String,
        external_aad_hex: String,
        sig_structure_hex: String,
        signature_hex: String,
        cose_sign1_tagged_hex: String,
        authority_snapshot: PublishedAuthoritySnapshot,
        verification_context: PublishedVerificationContext,
        mutations: Vec<PublishedMutation>,
    }

    #[derive(Debug, Deserialize)]
    struct PublishedAuthoritySnapshot {
        issuer: String,
        key_id: String,
        public_key_hex: String,
        authorized_roles: BTreeSet<String>,
        authorized_audiences: BTreeSet<String>,
        authority_epoch: u64,
        configuration_epoch: u64,
        key_valid_from_ms: u64,
        key_valid_until_ms: u64,
        revoked_at_ms: Option<u64>,
        observed_at_ms: u64,
    }

    #[derive(Debug, Deserialize)]
    struct PublishedVerificationContext {
        expected_record_profile: String,
        expected_record_version: u64,
        expected_record_kind: RecordKind,
        expected_record_digest: Digest32,
        expected_role: String,
        expected_audience: String,
        now_ms: u64,
        maximum_snapshot_age_ms: u64,
    }

    #[derive(Debug, Deserialize)]
    struct PublishedMutation {
        id: String,
        operation: String,
        expected_error: String,
        offset: Option<usize>,
        mask: Option<u8>,
        count: Option<usize>,
        from_hex: Option<String>,
        to_hex: Option<String>,
        hex: Option<String>,
        field: Option<String>,
        value: Option<String>,
    }

    fn decode_hex(input: &str) -> Result<Vec<u8>, AuthorityError> {
        if !input.len().is_multiple_of(2) {
            return Err(AuthorityError::InvalidField("vector_hex"));
        }
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = decode_hex_nibble(pair[0])?;
                let low = decode_hex_nibble(pair[1])?;
                Ok((high << 4) | low)
            })
            .collect()
    }

    fn decode_hex_nibble(value: u8) -> Result<u8, AuthorityError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err(AuthorityError::InvalidField("vector_hex")),
        }
    }

    fn rejected_verification(
        result: Result<VerifiedAuthority, AuthorityError>,
    ) -> Result<AuthorityError, AuthorityError> {
        match result {
            Ok(_) => Err(AuthorityError::InvalidField("mutation_expected_rejection")),
            Err(error) => Ok(error),
        }
    }

    fn rejected_signing(
        result: Result<Vec<u8>, AuthorityError>,
    ) -> Result<AuthorityError, AuthorityError> {
        match result {
            Ok(_) => Err(AuthorityError::InvalidField("mutation_expected_rejection")),
            Err(error) => Ok(error),
        }
    }

    fn digest() -> Digest32 {
        Digest32::from_payload(b"exact canonical ETP execution grant")
    }

    fn signer() -> Result<SigningAuthority, AuthorityError> {
        SigningAuthority::from_seed("spiffe://example.test/authority", "root-2026-09", [7; 32])
    }

    fn statement() -> AuthorityStatement {
        AuthorityStatement {
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
            record_digest: digest(),
            issued_at_ms: 1_000_000,
            not_before_ms: 1_000_000,
            expires_at_ms: 1_300_000,
            authority_epoch: 12,
            configuration_epoch: 41,
        }
    }

    fn snapshot(public_key: [u8; 32]) -> AuthoritySnapshot {
        AuthoritySnapshot {
            issuer: "spiffe://example.test/authority".to_owned(),
            key_id: "root-2026-09".to_owned(),
            public_key,
            authorized_roles: BTreeSet::from(["execution_authorizer".to_owned()]),
            authorized_audiences: BTreeSet::from(["executor:production-a".to_owned()]),
            authority_epoch: 12,
            configuration_epoch: 41,
            key_valid_from_ms: 900_000,
            key_valid_until_ms: 2_000_000,
            revoked_at_ms: None,
            observed_at_ms: NOW,
        }
    }

    fn context(record_digest: &Digest32) -> VerificationContext<'_> {
        VerificationContext {
            expected_record_profile: "effect-transaction/core/0.1",
            expected_record_version: 1,
            expected_record_kind: RecordKind::ExecutionGrant,
            expected_record_digest: record_digest,
            expected_role: "execution_authorizer",
            expected_audience: "executor:production-a",
            now_ms: NOW,
            maximum_snapshot_age_ms: 1_000,
        }
    }

    fn encoded_fixture() -> Result<(Vec<u8>, AuthoritySnapshot, Digest32), AuthorityError> {
        let signer = signer()?;
        let statement = statement();
        let encoded = signer.sign(&statement)?;
        Ok((encoded, snapshot(signer.public_key()), digest()))
    }

    #[test]
    fn verifies_exact_live_authority_binding() -> Result<(), AuthorityError> {
        let (encoded, snapshot, digest) = encoded_fixture()?;
        let verified = verify_authority(&encoded, &snapshot, context(&digest))?;
        assert_eq!(verified.statement(), &statement());
        assert_eq!(verified.verified_at_ms(), NOW);
        assert_eq!(verified.snapshot_observed_at_ms(), NOW);
        assert_eq!(
            verified.verifying_key_digest(),
            &Digest32::from_payload(&snapshot.public_key)
        );
        Ok(())
    }

    #[test]
    fn signature_mutation_is_rejected() -> Result<(), AuthorityError> {
        let (mut encoded, snapshot, digest) = encoded_fixture()?;
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn external_aad_domain_is_mandatory() -> Result<(), AuthorityError> {
        let signer = signer()?;
        let statement = statement();
        let payload = canonical_json(&statement).map_err(AuthorityError::Protocol)?;
        let cose = CoseSign1Builder::new()
            .protected(expected_header(signer.key_id()))
            .payload(payload)
            .create_signature(b"different-protocol/signature", |to_be_signed| {
                signer.key.sign(to_be_signed).to_bytes().to_vec()
            })
            .build()
            .to_tagged_vec()
            .map_err(|error| AuthorityError::MalformedCose(error.to_string()))?;
        let snapshot = snapshot(signer.public_key());
        let expected_digest = digest();
        assert!(matches!(
            verify_authority(&cose, &snapshot, context(&expected_digest)),
            Err(AuthorityError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn protected_content_type_is_mandatory() -> Result<(), AuthorityError> {
        let signer = signer()?;
        let statement = statement();
        let payload = canonical_json(&statement).map_err(AuthorityError::Protocol)?;
        let incomplete_header = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(signer.key_id().as_bytes().to_vec())
            .build();
        let aad = authority_external_aad(&statement)?;
        let cose = CoseSign1Builder::new()
            .protected(incomplete_header)
            .payload(payload)
            .create_signature(&aad, |to_be_signed| {
                signer.key.sign(to_be_signed).to_bytes().to_vec()
            })
            .build()
            .to_tagged_vec()
            .map_err(|error| AuthorityError::MalformedCose(error.to_string()))?;
        let snapshot = snapshot(signer.public_key());
        let expected_digest = digest();
        assert!(matches!(
            verify_authority(&cose, &snapshot, context(&expected_digest)),
            Err(AuthorityError::InvalidProtectedHeaders)
        ));
        Ok(())
    }

    #[test]
    fn wrong_key_is_rejected() -> Result<(), AuthorityError> {
        let (encoded, mut snapshot, digest) = encoded_fixture()?;
        snapshot.public_key = SigningAuthority::from_seed(
            "spiffe://example.test/authority",
            "root-2026-09",
            [8; 32],
        )?
        .public_key();
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn cross_record_and_profile_confusion_are_rejected() -> Result<(), AuthorityError> {
        let (encoded, snapshot, digest) = encoded_fixture()?;
        let mut wrong_kind = context(&digest);
        wrong_kind.expected_record_kind = RecordKind::EffectProposal;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, wrong_kind),
            Err(AuthorityError::RecordKindMismatch)
        ));

        let mut wrong_profile = context(&digest);
        wrong_profile.expected_record_profile = "vendor.example/effect/1";
        assert!(matches!(
            verify_authority(&encoded, &snapshot, wrong_profile),
            Err(AuthorityError::RecordProfileMismatch)
        ));
        Ok(())
    }

    #[test]
    fn substituted_record_digest_is_rejected() -> Result<(), AuthorityError> {
        let (encoded, snapshot, _) = encoded_fixture()?;
        let replacement = Digest32::from_payload(b"different grant");
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&replacement)),
            Err(AuthorityError::RecordDigestMismatch)
        ));
        Ok(())
    }

    #[test]
    fn role_and_audience_are_both_required_and_authorized() -> Result<(), AuthorityError> {
        let (encoded, mut snapshot, digest) = encoded_fixture()?;
        let mut wrong_role = context(&digest);
        wrong_role.expected_role = "policy_evaluator";
        assert!(matches!(
            verify_authority(&encoded, &snapshot, wrong_role),
            Err(AuthorityError::RoleMismatch)
        ));

        let mut wrong_audience = context(&digest);
        wrong_audience.expected_audience = "executor:staging";
        assert!(matches!(
            verify_authority(&encoded, &snapshot, wrong_audience),
            Err(AuthorityError::AudienceMismatch)
        ));

        snapshot.authorized_roles.clear();
        snapshot
            .authorized_roles
            .insert("policy_evaluator".to_owned());
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::RoleNotAuthorized)
        ));

        snapshot.authorized_roles = BTreeSet::from(["execution_authorizer".to_owned()]);
        snapshot.authorized_audiences = BTreeSet::from(["executor:staging".to_owned()]);
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::AudienceNotAuthorized)
        ));
        Ok(())
    }

    #[test]
    fn revocation_and_epoch_changes_invalidate_historical_signatures() -> Result<(), AuthorityError>
    {
        let (encoded, mut snapshot, digest) = encoded_fixture()?;
        snapshot.revoked_at_ms = Some(NOW);
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::KeyRevoked)
        ));

        snapshot.revoked_at_ms = None;
        snapshot.authority_epoch += 1;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::AuthorityEpochMismatch)
        ));

        snapshot.authority_epoch -= 1;
        snapshot.configuration_epoch += 1;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::ConfigurationEpochMismatch)
        ));
        Ok(())
    }

    #[test]
    fn stale_future_and_predating_snapshots_are_rejected() -> Result<(), AuthorityError> {
        let (encoded, mut snapshot, digest) = encoded_fixture()?;
        snapshot.observed_at_ms = NOW - 1_001;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::StaleSnapshot)
        ));

        snapshot.observed_at_ms = NOW + 1;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::SnapshotFromFuture)
        ));

        snapshot.observed_at_ms = 999_999;
        let mut broad = context(&digest);
        broad.maximum_snapshot_age_ms = 10_000;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, broad),
            Err(AuthorityError::SnapshotPredatesStatement)
        ));
        Ok(())
    }

    #[test]
    fn assertion_and_key_time_windows_are_fail_closed() -> Result<(), AuthorityError> {
        let signer = signer()?;
        let mut future_statement = statement();
        future_statement.not_before_ms = NOW + 1;
        future_statement.expires_at_ms = NOW + 1_001;
        let encoded = signer.sign(&future_statement)?;
        let snapshot = snapshot(signer.public_key());
        let expected_digest = digest();
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&expected_digest)),
            Err(AuthorityError::AssertionNotYetValid)
        ));

        let mut expired_statement = statement();
        expired_statement.expires_at_ms = NOW;
        let encoded = signer.sign(&expired_statement)?;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&expected_digest)),
            Err(AuthorityError::AssertionExpired)
        ));

        let (encoded, mut snapshot, digest) = encoded_fixture()?;
        snapshot.key_valid_until_ms = NOW;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context(&digest)),
            Err(AuthorityError::KeyExpired)
        ));

        Ok(())
    }

    #[test]
    fn assertion_cannot_be_backdated_before_key_validity() -> Result<(), AuthorityError> {
        let signing_authority = signer()?;
        let mut backdated = statement();
        backdated.issued_at_ms = 899_999;
        backdated.not_before_ms = 1_000_000;
        let encoded = signing_authority.sign(&backdated)?;
        let authority_snapshot = snapshot(signing_authority.public_key());
        let expected_digest = digest();
        assert!(matches!(
            verify_authority(&encoded, &authority_snapshot, context(&expected_digest)),
            Err(AuthorityError::KeyNotValidAtIssuance)
        ));
        Ok(())
    }

    #[test]
    fn signing_refuses_identity_mismatch_and_oversized_lifetime() -> Result<(), AuthorityError> {
        let signer = signer()?;
        let mut wrong_issuer = statement();
        wrong_issuer.issuer = "spiffe://attacker.invalid/authority".to_owned();
        assert!(matches!(
            signer.sign(&wrong_issuer),
            Err(AuthorityError::IssuerMismatch)
        ));

        let mut long_lived = statement();
        long_lived.expires_at_ms += 1;
        assert!(matches!(
            signer.sign(&long_lived),
            Err(AuthorityError::InvalidValidityInterval)
        ));
        Ok(())
    }

    #[test]
    fn overly_permissive_snapshot_age_policy_is_rejected() -> Result<(), AuthorityError> {
        let (encoded, snapshot, digest) = encoded_fixture()?;
        let mut context = context(&digest);
        context.maximum_snapshot_age_ms = MAX_AUTHORITY_SNAPSHOT_AGE_MS + 1;
        assert!(matches!(
            verify_authority(&encoded, &snapshot, context),
            Err(AuthorityError::SnapshotAgePolicyTooPermissive)
        ));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one end-to-end test keeps every published byte and mutation in a single audit path"
    )]
    fn published_authority_vector_is_exact_and_adversarial()
    -> Result<(), Box<dyn std::error::Error>> {
        let vector: PublishedAuthorityVector = serde_json::from_slice(AUTHORITY_VECTOR)?;
        assert_eq!(vector.profile, AUTHORITY_PROFILE);
        assert!(!vector.description.is_empty());

        let seed: [u8; 32] = decode_hex(&vector.seed_hex)?
            .try_into()
            .map_err(|_| AuthorityError::InvalidField("seed_hex"))?;
        let signing_authority = SigningAuthority::from_seed(
            vector.statement.issuer.clone(),
            vector.statement.key_id.clone(),
            seed,
        )?;
        let expected_public_key = decode_hex(&vector.public_key_hex)?;
        assert_eq!(
            signing_authority.public_key().as_slice(),
            expected_public_key
        );

        let encoded = signing_authority.sign(&vector.statement)?;
        assert_eq!(encoded, decode_hex(&vector.cose_sign1_tagged_hex)?);
        assert_eq!(encoded.first(), Some(&0xd2));
        let cose = CoseSign1::from_tagged_slice(&encoded)?;
        let protected =
            cose.protected.original_data.as_deref().ok_or_else(|| {
                AuthorityError::MalformedCose("missing protected bytes".to_owned())
            })?;
        let payload = cose
            .payload
            .as_deref()
            .ok_or(AuthorityError::MissingPayload)?;
        let external_aad = authority_external_aad(&vector.statement)?;
        assert_eq!(protected, decode_hex(&vector.protected_header_hex)?);
        assert_eq!(payload, decode_hex(&vector.payload_hex)?);
        assert_eq!(external_aad, decode_hex(&vector.external_aad_hex)?);
        assert_eq!(
            cose.tbs_data(&external_aad),
            decode_hex(&vector.sig_structure_hex)?
        );
        assert_eq!(cose.signature, decode_hex(&vector.signature_hex)?);

        let snapshot_public_key: [u8; 32] = decode_hex(&vector.authority_snapshot.public_key_hex)?
            .try_into()
            .map_err(|_| AuthorityError::InvalidField("snapshot_public_key_hex"))?;
        assert_eq!(snapshot_public_key.as_slice(), expected_public_key);
        let snapshot = AuthoritySnapshot {
            issuer: vector.authority_snapshot.issuer,
            key_id: vector.authority_snapshot.key_id,
            public_key: snapshot_public_key,
            authorized_roles: vector.authority_snapshot.authorized_roles,
            authorized_audiences: vector.authority_snapshot.authorized_audiences,
            authority_epoch: vector.authority_snapshot.authority_epoch,
            configuration_epoch: vector.authority_snapshot.configuration_epoch,
            key_valid_from_ms: vector.authority_snapshot.key_valid_from_ms,
            key_valid_until_ms: vector.authority_snapshot.key_valid_until_ms,
            revoked_at_ms: vector.authority_snapshot.revoked_at_ms,
            observed_at_ms: vector.authority_snapshot.observed_at_ms,
        };
        let verification_context = &vector.verification_context;
        let exact_context = VerificationContext {
            expected_record_profile: &verification_context.expected_record_profile,
            expected_record_version: verification_context.expected_record_version,
            expected_record_kind: verification_context.expected_record_kind,
            expected_record_digest: &verification_context.expected_record_digest,
            expected_role: &verification_context.expected_role,
            expected_audience: &verification_context.expected_audience,
            now_ms: verification_context.now_ms,
            maximum_snapshot_age_ms: verification_context.maximum_snapshot_age_ms,
        };
        verify_authority(&encoded, &snapshot, exact_context)?;

        for mutation in &vector.mutations {
            let error = match mutation.operation.as_str() {
                "xor_byte_from_end" => {
                    let offset = mutation
                        .offset
                        .ok_or(AuthorityError::InvalidField("mutation_offset"))?;
                    let mask = mutation
                        .mask
                        .ok_or(AuthorityError::InvalidField("mutation_mask"))?;
                    if offset == 0 || offset > encoded.len() {
                        return Err(AuthorityError::InvalidField("mutation_offset").into());
                    }
                    let mut mutated = encoded.clone();
                    let index = mutated.len() - offset;
                    mutated[index] ^= mask;
                    rejected_verification(verify_authority(&mutated, &snapshot, exact_context))?
                }
                "remove_prefix_bytes" => {
                    let count = mutation
                        .count
                        .ok_or(AuthorityError::InvalidField("mutation_count"))?;
                    if count > encoded.len() {
                        return Err(AuthorityError::InvalidField("mutation_count").into());
                    }
                    let mutated = encoded[count..].to_vec();
                    rejected_verification(verify_authority(&mutated, &snapshot, exact_context))?
                }
                "replace_prefix_hex" => {
                    let from = decode_hex(
                        mutation
                            .from_hex
                            .as_deref()
                            .ok_or(AuthorityError::InvalidField("mutation_from_hex"))?,
                    )?;
                    let to = decode_hex(
                        mutation
                            .to_hex
                            .as_deref()
                            .ok_or(AuthorityError::InvalidField("mutation_to_hex"))?,
                    )?;
                    if !encoded.starts_with(&from) {
                        return Err(AuthorityError::InvalidField("mutation_from_hex").into());
                    }
                    let mut mutated = to;
                    mutated.extend_from_slice(&encoded[from.len()..]);
                    rejected_verification(verify_authority(&mutated, &snapshot, exact_context))?
                }
                "append_hex" => {
                    let mut mutated = encoded.clone();
                    mutated.extend_from_slice(&decode_hex(
                        mutation
                            .hex
                            .as_deref()
                            .ok_or(AuthorityError::InvalidField("mutation_hex"))?,
                    )?);
                    rejected_verification(verify_authority(&mutated, &snapshot, exact_context))?
                }
                "verification_context_override" => {
                    if mutation.field.as_deref() != Some("expected_audience") {
                        return Err(AuthorityError::InvalidField("mutation_field").into());
                    }
                    let expected_audience = mutation
                        .value
                        .as_deref()
                        .ok_or(AuthorityError::InvalidField("mutation_value"))?;
                    let mutated_context = VerificationContext {
                        expected_audience,
                        ..exact_context
                    };
                    rejected_verification(verify_authority(&encoded, &snapshot, mutated_context))?
                }
                "statement_repeat" => {
                    if mutation.field.as_deref() != Some("issuer") {
                        return Err(AuthorityError::InvalidField("mutation_field").into());
                    }
                    let value = mutation
                        .value
                        .as_deref()
                        .ok_or(AuthorityError::InvalidField("mutation_value"))?;
                    let count = mutation
                        .count
                        .ok_or(AuthorityError::InvalidField("mutation_count"))?;
                    let mut mutated = vector.statement.clone();
                    mutated.issuer = value.repeat(count);
                    rejected_signing(signing_authority.sign(&mutated))?
                }
                _ => return Err(AuthorityError::InvalidField("mutation_operation").into()),
            };
            assert_eq!(error.code(), mutation.expected_error, "{}", mutation.id);
        }
        assert_eq!(vector.mutations.len(), 7);
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            failure_persistence: None,
            rng_seed: RngSeed::Fixed(0x4554_502D_434F_5345),
            ..ProptestConfig::default()
        })]

        #[test]
        // One CBOR data item can have multiple encodings. A byte difference is not sufficient
        // evidence of a semantic change. Accept a mutation only if deterministic re-encoding
        // produces the original canonical COSE object.
        fn single_byte_cose_mutation_is_rejected_unless_it_reencodes_the_exact_input(
            raw_index in any::<usize>(),
            mask in 1u8..=u8::MAX,
        ) {
            let (encoded, snapshot, digest) = match encoded_fixture() {
                Ok(fixture) => fixture,
                Err(error) => return Err(TestCaseError::fail(format!(
                    "failed to construct authority fixture: {error}"
                ))),
            };
            let mut mutated = encoded.clone();
            let index = raw_index % mutated.len();
            mutated[index] ^= mask;
            prop_assert_ne!(mutated.as_slice(), encoded.as_slice());

            if verify_authority(&mutated, &snapshot, context(&digest)).is_ok() {
                let parsed = match CoseSign1::from_tagged_slice(&mutated) {
                    Ok(value) => value,
                    Err(error) => return Err(TestCaseError::fail(format!(
                        "failed to decode accepted mutation: {error}"
                    ))),
                };
                let reencoded = match parsed.to_tagged_vec() {
                    Ok(value) => value,
                    Err(error) => return Err(TestCaseError::fail(format!(
                        "failed to re-encode accepted mutation: {error}"
                    ))),
                };
                prop_assert_eq!(
                    reencoded.as_slice(),
                    encoded.as_slice(),
                    "accepted mutation does not encode the original canonical object"
                );
            }
        }
    }
}

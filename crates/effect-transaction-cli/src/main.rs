#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use effect_transaction_core::{
    AuthorizationDecision, EffectProposal, EffectReceipt, ExecutionGrant,
    MAX_TRANSPORT_INPUT_BYTES, ProtocolRecord, ReconciliationRecord, TaskCommitment,
    TransactionBundle, parse_record, verify_transaction,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

const CORE_PROFILE: &str = "effect-transaction/core/0.1";

#[derive(Debug, Parser)]
#[command(
    name = "etp",
    version,
    about = "Verify ETP transactions and compute record commitments"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify an ETP transaction or test-vector envelope.
    Verify {
        /// Path to the JSON input file.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Write JSON on one line.
        #[arg(long)]
        compact: bool,
    },
    /// Validate an ETP record and compute its commitment.
    Hash {
        /// ETP record kind.
        #[arg(value_name = "KIND")]
        kind: RecordKind,
        /// Path to the JSON record.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Write JSON on one line.
        #[arg(long)]
        compact: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RecordKind {
    TaskCommitment,
    EffectProposal,
    AuthorizationDecision,
    ExecutionGrant,
    EffectReceipt,
    ReconciliationRecord,
}

impl RecordKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TaskCommitment => "task_commitment",
            Self::EffectProposal => "effect_proposal",
            Self::AuthorizationDecision => "authorization_decision",
            Self::ExecutionGrant => "execution_grant",
            Self::EffectReceipt => "effect_receipt",
            Self::ReconciliationRecord => "reconciliation_record",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorEnvelope {
    profile: String,
    #[serde(default)]
    description: Option<String>,
    transaction: TransactionBundle,
    expected: Value,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VerifyInput {
    Vector(VectorEnvelope),
    Transaction(TransactionBundle),
}

#[derive(Debug, Error)]
enum CliError {
    #[error("failed to read input: {0}")]
    Io(#[from] std::io::Error),
    #[error("input exceeds the ETP transport limit")]
    InputTooLarge,
    #[error("invalid JSON structure: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported transaction profile: {0}")]
    UnsupportedProfile(String),
    #[error("transaction rejected: {0}")]
    Protocol(#[from] effect_transaction_core::ProtocolError),
    #[error("computed result does not match test-vector expectations")]
    ExpectedMismatch,
    #[error("test-vector description is invalid")]
    InvalidVectorDescription,
}

impl CliError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "io_error",
            Self::InputTooLarge => "transport_limit",
            Self::Json(_) => "invalid_json",
            Self::UnsupportedProfile(_) => "unsupported_profile",
            Self::Protocol(_) => "protocol_reject",
            Self::ExpectedMismatch => "expected_mismatch",
            Self::InvalidVectorDescription => "invalid_vector_description",
        }
    }
}

#[derive(Debug, Serialize)]
struct HashOutput<'a> {
    valid: bool,
    kind: &'a str,
    digest: &'a str,
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, CliError> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(MAX_TRANSPORT_INPUT_BYTES.min(64 * 1024));
    file.take((MAX_TRANSPORT_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_TRANSPORT_INPUT_BYTES {
        return Err(CliError::InputTooLarge);
    }
    Ok(bytes)
}

fn strict_deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CliError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn verified_json(bytes: &[u8]) -> Result<Value, CliError> {
    let input: VerifyInput = strict_deserialize(bytes)?;
    let (bundle, expected) = match input {
        VerifyInput::Vector(vector) => {
            if vector.profile != CORE_PROFILE {
                return Err(CliError::UnsupportedProfile(vector.profile));
            }
            if vector.description.as_ref().is_some_and(|description| {
                description.chars().count() > 4096 || description.chars().any(char::is_control)
            }) {
                return Err(CliError::InvalidVectorDescription);
            }
            (vector.transaction, Some(vector.expected))
        }
        VerifyInput::Transaction(bundle) => (bundle, None),
    };
    let verified = verify_transaction(&bundle)?;
    let value = serde_json::to_value(verified)?;
    if expected.as_ref().is_some_and(|expected| expected != &value) {
        return Err(CliError::ExpectedMismatch);
    }
    let Value::Object(mut object) = value else {
        return Err(CliError::ExpectedMismatch);
    };
    object.insert("valid".into(), Value::Bool(true));
    Ok(Value::Object(object))
}

fn record_digest<T>(bytes: &[u8]) -> Result<effect_transaction_core::Digest32, CliError>
where
    T: DeserializeOwned + ProtocolRecord,
{
    Ok(parse_record::<T>(bytes)?.commitment()?)
}

fn hash_json(kind: RecordKind, bytes: &[u8]) -> Result<Value, CliError> {
    let digest = match kind {
        RecordKind::TaskCommitment => record_digest::<TaskCommitment>(bytes)?,
        RecordKind::EffectProposal => record_digest::<EffectProposal>(bytes)?,
        RecordKind::AuthorizationDecision => record_digest::<AuthorizationDecision>(bytes)?,
        RecordKind::ExecutionGrant => record_digest::<ExecutionGrant>(bytes)?,
        RecordKind::EffectReceipt => record_digest::<EffectReceipt>(bytes)?,
        RecordKind::ReconciliationRecord => record_digest::<ReconciliationRecord>(bytes)?,
    };
    Ok(serde_json::to_value(HashOutput {
        valid: true,
        kind: kind.as_str(),
        digest: digest.as_str(),
    })?)
}

fn print_json(value: &Value, compact: bool) -> Result<(), CliError> {
    let output = if compact {
        serde_json::to_string(value)?
    } else {
        serde_json::to_string_pretty(value)?
    };
    println!("{output}");
    Ok(())
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Verify { path, compact } => {
            let bytes = read_bounded(&path)?;
            print_json(&verified_json(&bytes)?, compact)
        }
        Command::Hash {
            kind,
            path,
            compact,
        } => {
            let bytes = read_bounded(&path)?;
            print_json(&hash_json(kind, &bytes)?, compact)
        }
    }
}

fn error_json(error: &CliError) -> Value {
    let mut object = Map::new();
    object.insert("valid".into(), Value::Bool(false));
    object.insert("code".into(), Value::String(error.code().into()));
    object.insert("message".into(), Value::String(error.to_string()));
    Value::Object(object)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error_json(&error));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &[u8] = include_bytes!("../test-vectors/positive-chain.json");

    #[test]
    fn verifies_the_published_cross_language_vector() -> Result<(), CliError> {
        let value = verified_json(VECTOR)?;
        assert_eq!(value["valid"], true);
        assert_eq!(value["state"], "effect_confirmed");
        Ok(())
    }

    #[test]
    fn refuses_an_unregistered_profile_and_expected_divergence() {
        let changed_profile = String::from_utf8_lossy(VECTOR).replacen(
            CORE_PROFILE,
            "effect-transaction/core/9.9",
            1,
        );
        assert!(matches!(
            verified_json(changed_profile.as_bytes()),
            Err(CliError::UnsupportedProfile(_))
        ));

        let changed_expectation = String::from_utf8_lossy(VECTOR).replacen(
            "\"state\": \"effect_confirmed\"",
            "\"state\": \"succeeded\"",
            1,
        );
        assert!(matches!(
            verified_json(changed_expectation.as_bytes()),
            Err(CliError::ExpectedMismatch)
        ));
    }

    #[test]
    fn keeps_bare_transactions_separate_from_strict_vector_envelopes() -> Result<(), CliError> {
        let vector: Value = serde_json::from_slice(VECTOR)?;
        let bare = serde_json::to_vec(&vector["transaction"])?;
        let verified = verified_json(&bare)?;
        assert_eq!(verified["state"], "effect_confirmed");

        let mut missing_expected = vector.clone();
        let Some(missing_expected_object) = missing_expected.as_object_mut() else {
            return Err(CliError::ExpectedMismatch);
        };
        missing_expected_object.remove("expected");
        assert!(matches!(
            verified_json(&serde_json::to_vec(&missing_expected)?),
            Err(CliError::Json(_))
        ));

        let mut unknown_metadata = vector;
        let Some(unknown_metadata_object) = unknown_metadata.as_object_mut() else {
            return Err(CliError::ExpectedMismatch);
        };
        unknown_metadata_object.insert("model_comment".into(), Value::String("untrusted".into()));
        assert!(matches!(
            verified_json(&serde_json::to_vec(&unknown_metadata)?),
            Err(CliError::Json(_))
        ));
        Ok(())
    }
}

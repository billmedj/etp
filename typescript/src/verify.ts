import { canonicalJson, commitment, compareUnicodeScalars } from "./canonical.ts";
import {
  DOMAINS,
  VERSION,
  type AuthorizationDecision,
  type DecisionOutcome,
  type Digest,
  type EffectProposal,
  type EffectReceipt,
  type EffectTransactionBundle,
  type ExecutionGrant,
  type ReceiptOutcome,
  type ReconciliationOutcome,
  type ReconciliationRecord,
  type TaskCommitment,
  type VerifiedTransaction,
} from "./model.ts";

export const MAX_RECONCILIATION_RECORDS = 10_000;

export class VerificationError extends Error {
  readonly code: string;
  readonly path: string;

  constructor(code: string, path: string, message: string) {
    super(`${path}: ${message}`);
    this.name = "VerificationError";
    this.code = code;
    this.path = path;
  }
}

function fail(code: string, path: string, message: string): never {
  throw new VerificationError(code, path, message);
}

function objectAt(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("record_type", path, "expected a JSON object");
  }
  canonicalJson(value);
  return value as Record<string, unknown>;
}

function exactFields(
  value: unknown,
  path: string,
  fields: readonly string[],
): Record<string, unknown> {
  const record = objectAt(value, path);
  const expected = new Set(fields);
  for (const field of fields) {
    if (!Object.hasOwn(record, field)) {
      fail("missing_field", `${path}.${field}`, "required field is missing");
    }
  }
  for (const field of Object.keys(record)) {
    if (!expected.has(field)) {
      fail("unknown_field", `${path}.${field}`, "field is not permitted");
    }
  }
  return record;
}

function literalOne(value: unknown, path: string): 1 {
  if (value !== VERSION) fail("version", path, "expected version 1");
  return VERSION;
}

function singleUse(value: unknown, path: string): 1 {
  if (value !== 1) fail("single_use", path, "expected value 1");
  return 1;
}

function text(
  value: unknown,
  path: string,
  maximum = 1024,
): string {
  if (typeof value !== "string") fail("string", path, "expected a string");
  if (value.length === 0 || /^\s|\s$/u.test(value)) {
    fail("string", path, "must not be empty or have surrounding whitespace");
  }
  if (Buffer.byteLength(value, "utf8") > maximum) {
    fail("string_length", path, `must not exceed ${maximum} UTF-8 bytes`);
  }
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    fail("control_character", path, "control characters are not permitted");
  }
  canonicalJson(value);
  return value;
}

function identifier(value: unknown, path: string): string {
  return text(value, path, 256);
}

function nonemptyText(value: unknown, path: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0) {
    fail("string", path, "expected a non-empty string");
  }
  if (Buffer.byteLength(value, "utf8") > maximum) {
    fail("string_length", path, `must not exceed ${maximum} UTF-8 bytes`);
  }
  if (/^\s|\s$/u.test(value)) {
    fail("string", path, "leading and trailing whitespace are not allowed");
  }
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    fail("control_character", path, "control characters are not permitted");
  }
  canonicalJson(value);
  return value;
}

function digest(value: unknown, path: string): Digest {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    fail("digest", path, "expected sha256 followed by 64 lowercase hexadecimal digits");
  }
  if (value === `sha256:${"0".repeat(64)}`) {
    fail("digest", path, "all-zero digest is not permitted");
  }
  return value as Digest;
}

function integer(value: unknown, path: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    fail("integer", path, `expected a safe integer >= ${minimum}`);
  }
  if (Object.is(value, -0)) fail("integer", path, "negative zero is not permitted");
  return value as number;
}

function timestamp(value: unknown, path: string): number {
  return integer(value, path, 0);
}

function digestArray(value: unknown, path: string, maximumItems: number): Digest[] {
  if (!Array.isArray(value)) fail("array", path, "expected an array");
  if (value.length > maximumItems) {
    fail("array_length", path, `must not contain more than ${maximumItems} items`);
  }
  return value.map((item, index) => digest(item, `${path}[${index}]`));
}

function operationToken(value: unknown, path: string): string {
  const result = text(value, path, 256);
  if (!/^[a-z][a-z0-9._:/-]*$/u.test(result)) {
    fail("operation", path, "expected a lowercase operation token");
  }
  return result;
}

function reasonCode(value: unknown, path: string): string {
  const result = text(value, path, 256);
  if (!/^[a-z][a-z0-9._:/-]*$/u.test(result)) {
    fail("reason_code", path, "expected a lowercase reason-code token");
  }
  return result;
}

function nonce(value: unknown, path: string): string {
  const result = text(value, path, 128);
  if (!/^[A-Za-z0-9_-]{22,128}$/u.test(result)) {
    fail("nonce", path, "expected 22 to 128 unpadded base64url characters");
  }
  return result;
}

function sortedUnique(values: readonly string[], path: string): void {
  for (let index = 1; index < values.length; index += 1) {
    const order = compareUnicodeScalars(values[index - 1], values[index]);
    if (order === 0) fail("duplicate_item", `${path}[${index}]`, "duplicate item");
    if (order > 0) fail("unsorted_array", path, "items must be sorted canonically");
  }
}

function enumValue<T extends string>(
  value: unknown,
  path: string,
  accepted: readonly T[],
): T {
  if (typeof value !== "string" || !(accepted as readonly string[]).includes(value)) {
    fail("enum", path, `expected one of: ${accepted.join(", ")}`);
  }
  return value as T;
}

function equal(actual: unknown, expected: unknown, path: string): void {
  if (actual !== expected) {
    fail("binding_mismatch", path, `expected ${String(expected)}, received ${String(actual)}`);
  }
}

function ordered(start: number, end: number, path: string): void {
  if (end <= start) fail("invalid_window", path, "end must be greater than start");
}

export function validateTaskCommitment(value: unknown): TaskCommitment {
  const path = "commitment";
  const record = exactFields(value, path, [
    "version", "commitment_id", "principal", "objective_digest",
    "constraints_digest", "authority_scope_digest", "policy_epoch",
    "configuration_epoch", "created_at_ms", "expires_at_ms",
  ]);
  const result: TaskCommitment = {
    version: literalOne(record.version, `${path}.version`),
    commitment_id: identifier(record.commitment_id, `${path}.commitment_id`),
    principal: text(record.principal, `${path}.principal`, 512),
    objective_digest: digest(record.objective_digest, `${path}.objective_digest`),
    constraints_digest: digest(record.constraints_digest, `${path}.constraints_digest`),
    authority_scope_digest: digest(record.authority_scope_digest, `${path}.authority_scope_digest`),
    policy_epoch: integer(record.policy_epoch, `${path}.policy_epoch`),
    configuration_epoch: integer(record.configuration_epoch, `${path}.configuration_epoch`),
    created_at_ms: timestamp(record.created_at_ms, `${path}.created_at_ms`),
    expires_at_ms: timestamp(record.expires_at_ms, `${path}.expires_at_ms`),
  };
  ordered(result.created_at_ms, result.expires_at_ms, `${path}.expires_at_ms`);
  return result;
}

export function validateEffectProposal(value: unknown): EffectProposal {
  const path = "proposal";
  const record = exactFields(value, path, [
    "version", "proposal_id", "commitment_hash", "effect_profile", "operation",
    "target", "arguments_digest", "expected_effect_digest", "pre_state_digest",
    "resource_claim_digest", "created_at_ms", "expires_at_ms",
  ]);
  const result: EffectProposal = {
    version: literalOne(record.version, `${path}.version`),
    proposal_id: identifier(record.proposal_id, `${path}.proposal_id`),
    commitment_hash: digest(record.commitment_hash, `${path}.commitment_hash`),
    effect_profile: text(record.effect_profile, `${path}.effect_profile`, 256),
    operation: operationToken(record.operation, `${path}.operation`),
    target: nonemptyText(record.target, `${path}.target`, 4096),
    arguments_digest: digest(record.arguments_digest, `${path}.arguments_digest`),
    expected_effect_digest: digest(record.expected_effect_digest, `${path}.expected_effect_digest`),
    pre_state_digest: digest(record.pre_state_digest, `${path}.pre_state_digest`),
    resource_claim_digest: digest(record.resource_claim_digest, `${path}.resource_claim_digest`),
    created_at_ms: timestamp(record.created_at_ms, `${path}.created_at_ms`),
    expires_at_ms: timestamp(record.expires_at_ms, `${path}.expires_at_ms`),
  };
  ordered(result.created_at_ms, result.expires_at_ms, `${path}.expires_at_ms`);
  return result;
}

export function validateAuthorizationDecision(value: unknown): AuthorizationDecision {
  const path = "decision";
  const record = exactFields(value, path, [
    "version", "decision_id", "proposal_hash", "evidence_hashes", "outcome",
    "reason_codes", "decided_at_ms", "expires_at_ms",
  ]);
  const evidenceHashes = digestArray(record.evidence_hashes, `${path}.evidence_hashes`, 256);
  if (!Array.isArray(record.reason_codes)) {
    fail("array", `${path}.reason_codes`, "expected an array");
  }
  if (record.reason_codes.length > 64) {
    fail("array_length", `${path}.reason_codes`, "must not contain more than 64 items");
  }
  const reasonCodes = record.reason_codes.map((item, index) =>
    reasonCode(item, `${path}.reason_codes[${index}]`));
  sortedUnique(evidenceHashes, `${path}.evidence_hashes`);
  sortedUnique(reasonCodes, `${path}.reason_codes`);
  if (reasonCodes.length === 0) {
    fail("reason_required", `${path}.reason_codes`, "at least one reason code is required");
  }
  const outcome = enumValue<DecisionOutcome>(record.outcome, `${path}.outcome`, [
    "allow", "deny", "review",
  ]);
  if (outcome === "allow" && evidenceHashes.length === 0) {
    fail("evidence_required", `${path}.evidence_hashes`, "allow requires at least one evidence digest");
  }
  const result: AuthorizationDecision = {
    version: literalOne(record.version, `${path}.version`),
    decision_id: identifier(record.decision_id, `${path}.decision_id`),
    proposal_hash: digest(record.proposal_hash, `${path}.proposal_hash`),
    evidence_hashes: evidenceHashes,
    outcome,
    reason_codes: reasonCodes,
    decided_at_ms: timestamp(record.decided_at_ms, `${path}.decided_at_ms`),
    expires_at_ms: timestamp(record.expires_at_ms, `${path}.expires_at_ms`),
  };
  ordered(result.decided_at_ms, result.expires_at_ms, `${path}.expires_at_ms`);
  return result;
}

export function validateExecutionGrant(value: unknown): ExecutionGrant {
  const path = "grant";
  const record = exactFields(value, path, [
    "version", "grant_id", "proposal_hash", "decision_hash", "audience",
    "not_before_ms", "expires_at_ms", "uses", "nonce",
  ]);
  const result: ExecutionGrant = {
    version: literalOne(record.version, `${path}.version`),
    grant_id: identifier(record.grant_id, `${path}.grant_id`),
    proposal_hash: digest(record.proposal_hash, `${path}.proposal_hash`),
    decision_hash: digest(record.decision_hash, `${path}.decision_hash`),
    audience: text(record.audience, `${path}.audience`, 512),
    not_before_ms: timestamp(record.not_before_ms, `${path}.not_before_ms`),
    expires_at_ms: timestamp(record.expires_at_ms, `${path}.expires_at_ms`),
    uses: singleUse(record.uses, `${path}.uses`),
    nonce: nonce(record.nonce, `${path}.nonce`),
  };
  ordered(result.not_before_ms, result.expires_at_ms, `${path}.expires_at_ms`);
  if (result.expires_at_ms - result.not_before_ms > 300_000) {
    fail("grant_lifetime", `${path}.expires_at_ms`, "grant lifetime exceeds 300000 ms");
  }
  return result;
}

export function validateEffectReceipt(value: unknown): EffectReceipt {
  const path = "receipt";
  const record = exactFields(value, path, [
    "version", "receipt_id", "proposal_hash", "grant_hash", "attempt_id",
    "claimed_at_ms", "dispatched_at_ms", "completed_at_ms", "outcome",
    "observation_digest",
  ]);
  const dispatchedAt = record.dispatched_at_ms === null
    ? null
    : timestamp(record.dispatched_at_ms, `${path}.dispatched_at_ms`);
  const result: EffectReceipt = {
    version: literalOne(record.version, `${path}.version`),
    receipt_id: identifier(record.receipt_id, `${path}.receipt_id`),
    proposal_hash: digest(record.proposal_hash, `${path}.proposal_hash`),
    grant_hash: digest(record.grant_hash, `${path}.grant_hash`),
    attempt_id: identifier(record.attempt_id, `${path}.attempt_id`),
    claimed_at_ms: timestamp(record.claimed_at_ms, `${path}.claimed_at_ms`),
    dispatched_at_ms: dispatchedAt,
    completed_at_ms: timestamp(record.completed_at_ms, `${path}.completed_at_ms`),
    outcome: enumValue<ReceiptOutcome>(record.outcome, `${path}.outcome`, [
      "succeeded", "failed", "not_dispatched", "unknown",
    ]),
    observation_digest: digest(record.observation_digest, `${path}.observation_digest`),
  };
  if (result.completed_at_ms < result.claimed_at_ms) {
    fail("invalid_timeline", `${path}.completed_at_ms`, "completion precedes claim");
  }
  if (result.dispatched_at_ms !== null) {
    if (result.dispatched_at_ms < result.claimed_at_ms) {
      fail("invalid_timeline", `${path}.dispatched_at_ms`, "dispatch precedes claim");
    }
    if (result.completed_at_ms < result.dispatched_at_ms) {
      fail("invalid_timeline", `${path}.completed_at_ms`, "completion precedes dispatch");
    }
  }
  if (["succeeded", "failed"].includes(result.outcome) && result.dispatched_at_ms === null) {
    fail("receipt_dispatch", `${path}.dispatched_at_ms`, `${result.outcome} requires a dispatch time`);
  }
  if (result.outcome === "not_dispatched" && result.dispatched_at_ms !== null) {
    fail("receipt_dispatch", `${path}.dispatched_at_ms`, "not_dispatched requires a null dispatch time");
  }
  return result;
}

export function validateReconciliationRecord(value: unknown): ReconciliationRecord {
  const path = "reconciliation";
  const record = exactFields(value, path, [
    "version", "reconciliation_id", "receipt_hash", "sequence",
    "parent_reconciliation_hash", "observed_at_ms", "outcome", "evidence_digest",
  ]);
  const parent = record.parent_reconciliation_hash === null
    ? null
    : digest(record.parent_reconciliation_hash, `${path}.parent_reconciliation_hash`);
  return {
    version: literalOne(record.version, `${path}.version`),
    reconciliation_id: identifier(record.reconciliation_id, `${path}.reconciliation_id`),
    receipt_hash: digest(record.receipt_hash, `${path}.receipt_hash`),
    sequence: integer(record.sequence, `${path}.sequence`, 1),
    parent_reconciliation_hash: parent,
    observed_at_ms: timestamp(record.observed_at_ms, `${path}.observed_at_ms`),
    outcome: enumValue<ReconciliationOutcome>(record.outcome, `${path}.outcome`, [
      "effect_confirmed", "no_effect_confirmed", "partial_effect", "still_unknown",
      "compensated",
    ]),
    evidence_digest: digest(record.evidence_digest, `${path}.evidence_digest`),
  };
}

export const hashTaskCommitment = (record: TaskCommitment): Digest =>
  commitment(DOMAINS.task_commitment, record) as Digest;
export const hashEffectProposal = (record: EffectProposal): Digest =>
  commitment(DOMAINS.effect_proposal, record) as Digest;
export const hashAuthorizationDecision = (record: AuthorizationDecision): Digest =>
  commitment(DOMAINS.authorization_decision, record) as Digest;
export const hashExecutionGrant = (record: ExecutionGrant): Digest =>
  commitment(DOMAINS.execution_grant, record) as Digest;
export const hashEffectReceipt = (record: EffectReceipt): Digest =>
  commitment(DOMAINS.effect_receipt, record) as Digest;
export const hashReconciliationRecord = (record: ReconciliationRecord): Digest =>
  commitment(DOMAINS.reconciliation_record, record) as Digest;

export function verifyTransaction(value: unknown): VerifiedTransaction {
  const bundle = objectAt(value, "transaction");
  const allowedBundleFields = new Set([
    "commitment", "proposal", "decision", "grant", "receipt", "reconciliations",
  ]);
  for (const field of Object.keys(bundle)) {
    if (!allowedBundleFields.has(field)) {
      fail("unknown_field", `transaction.${field}`, "unknown bundle field");
    }
  }
  for (const required of ["commitment", "proposal", "decision"] as const) {
    if (!Object.hasOwn(bundle, required)) {
      fail("missing_field", `transaction.${required}`, "required record is missing");
    }
  }

  const task = validateTaskCommitment(bundle.commitment);
  const taskHash = hashTaskCommitment(task);
  const proposal = validateEffectProposal(bundle.proposal);
  const proposalHash = hashEffectProposal(proposal);
  equal(proposal.commitment_hash, taskHash, "proposal.commitment_hash");
  if (proposal.created_at_ms < task.created_at_ms) {
    fail("invalid_timeline", "proposal.created_at_ms", "proposal predates commitment");
  }
  if (proposal.expires_at_ms > task.expires_at_ms) {
    fail("invalid_window", "proposal.expires_at_ms", "proposal outlives commitment");
  }

  const decision = validateAuthorizationDecision(bundle.decision);
  const decisionHash = hashAuthorizationDecision(decision);
  equal(decision.proposal_hash, proposalHash, "decision.proposal_hash");
  if (decision.decided_at_ms < proposal.created_at_ms) {
    fail("invalid_timeline", "decision.decided_at_ms", "decision predates proposal");
  }
  if (decision.expires_at_ms > proposal.expires_at_ms) {
    fail("invalid_window", "decision.expires_at_ms", "decision outlives proposal");
  }

  const grantValue = Object.hasOwn(bundle, "grant") ? bundle.grant : null;
  const receiptValue = Object.hasOwn(bundle, "receipt") ? bundle.receipt : null;
  const reconciliationValue = Object.hasOwn(bundle, "reconciliations")
    ? bundle.reconciliations
    : [];
  if (!Array.isArray(reconciliationValue)) {
    fail("array", "transaction.reconciliations", "expected an array");
  }
  if (reconciliationValue.length > MAX_RECONCILIATION_RECORDS) {
    fail(
      "array_length",
      "transaction.reconciliations",
      `must not contain more than ${MAX_RECONCILIATION_RECORDS} records`,
    );
  }

  if (grantValue === null || grantValue === undefined) {
    if (receiptValue !== null && receiptValue !== undefined) {
      fail("missing_predecessor", "transaction.receipt", "receipt requires a grant");
    }
    if (reconciliationValue.length > 0) {
      fail("missing_predecessor", "transaction.reconciliations", "reconciliation requires a receipt");
    }
    return {
      commitment_hash: taskHash,
      proposal_hash: proposalHash,
      decision_hash: decisionHash,
      grant_hash: null,
      receipt_hash: null,
      reconciliation_hashes: [],
      state: "decided",
    };
  }

  if (decision.outcome !== "allow") {
    fail("nonauthorizing_decision", "decision.outcome", "only allow can produce a grant");
  }
  const grant = validateExecutionGrant(grantValue);
  const grantHash = hashExecutionGrant(grant);
  equal(grant.proposal_hash, proposalHash, "grant.proposal_hash");
  equal(grant.decision_hash, decisionHash, "grant.decision_hash");
  if (grant.not_before_ms < decision.decided_at_ms) {
    fail("invalid_timeline", "grant.not_before_ms", "grant predates decision");
  }
  if (grant.expires_at_ms > decision.expires_at_ms) {
    fail("invalid_window", "grant.expires_at_ms", "grant outlives decision");
  }

  if (receiptValue === null || receiptValue === undefined) {
    if (reconciliationValue.length > 0) {
      fail("missing_predecessor", "transaction.reconciliations", "reconciliation requires a receipt");
    }
    return {
      commitment_hash: taskHash,
      proposal_hash: proposalHash,
      decision_hash: decisionHash,
      grant_hash: grantHash,
      receipt_hash: null,
      reconciliation_hashes: [],
      state: "granted",
    };
  }

  const receipt = validateEffectReceipt(receiptValue);
  const receiptHash = hashEffectReceipt(receipt);
  equal(receipt.proposal_hash, proposalHash, "receipt.proposal_hash");
  equal(receipt.grant_hash, grantHash, "receipt.grant_hash");
  if (receipt.claimed_at_ms < grant.not_before_ms) {
    fail("premature_claim", "receipt.claimed_at_ms", "grant was not active at claim time");
  }
  if (receipt.claimed_at_ms >= grant.expires_at_ms) {
    fail("expired_claim", "receipt.claimed_at_ms", "grant was expired at claim time");
  }

  if (reconciliationValue.length > 0 && receipt.outcome !== "unknown") {
    fail("invalid_reconciliation", "transaction.reconciliations", "only unknown receipts are reconciled");
  }

  const reconciliationHashes: Digest[] = [];
  let prior: ReconciliationRecord | null = null;
  let priorHash: Digest | null = null;
  let terminal = false;
  const reconciliationIdentifiers = new Set<string>();
  for (let index = 0; index < reconciliationValue.length; index += 1) {
    if (terminal) {
      fail("terminal_reconciliation", `transaction.reconciliations[${index}]`, "record follows a terminal outcome");
    }
    const current = validateReconciliationRecord(reconciliationValue[index]);
    if (reconciliationIdentifiers.has(current.reconciliation_id)) {
      fail(
        "duplicate_identifier",
        `transaction.reconciliations[${index}].reconciliation_id`,
        "reconciliation identifier is already used in this chain",
      );
    }
    reconciliationIdentifiers.add(current.reconciliation_id);
    equal(current.receipt_hash, receiptHash, `transaction.reconciliations[${index}].receipt_hash`);
    equal(current.sequence, index + 1, `transaction.reconciliations[${index}].sequence`);
    equal(current.parent_reconciliation_hash, priorHash, `transaction.reconciliations[${index}].parent_reconciliation_hash`);
    const lowerTime = prior === null ? receipt.completed_at_ms : prior.observed_at_ms;
    if (current.observed_at_ms < lowerTime) {
      fail("invalid_timeline", `transaction.reconciliations[${index}].observed_at_ms`, "observation time moved backwards");
    }
    const currentHash = hashReconciliationRecord(current);
    reconciliationHashes.push(currentHash);
    prior = current;
    priorHash = currentHash;
    terminal = ["effect_confirmed", "no_effect_confirmed", "compensated"].includes(current.outcome);
  }

  const state = prior === null ? receipt.outcome : prior.outcome;
  return {
    commitment_hash: taskHash,
    proposal_hash: proposalHash,
    decision_hash: decisionHash,
    grant_hash: grantHash,
    receipt_hash: receiptHash,
    reconciliation_hashes: reconciliationHashes,
    state,
  };
}

export function asBundle(value: unknown): EffectTransactionBundle {
  verifyTransaction(value);
  return value as EffectTransactionBundle;
}

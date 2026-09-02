#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  CanonicalizationError,
  MAX_TRANSPORT_INPUT_BYTES,
  MAX_TRANSPORT_NESTING_DEPTH,
  MAX_TRANSPORT_NODES,
  canonicalJson,
  parseStrictJson,
} from "../typescript/src/canonical.ts";
import {
  VerificationError,
  MAX_RECONCILIATION_RECORDS,
  hashAuthorizationDecision,
  hashReconciliationRecord,
  verifyTransaction,
} from "../typescript/src/verify.ts";

type JsonObject = Record<string, any>;

interface ExpectedObservation {
  verdict: "accept" | "reject";
  code?: string;
  state?: string;
  canonical?: string;
  successful_claims?: number;
  rejected_claims?: number;
  receipt_writes?: number;
}

interface ManifestCase {
  id: string;
  category: string;
  expected: ExpectedObservation;
}

interface Manifest {
  suite: string;
  suite_version: number;
  profile: string;
  cases: ManifestCase[];
}

interface MutationCase {
  id: string;
  pointer: string;
  replacement: unknown;
  also?: Array<{ pointer: string; replacement: unknown }>;
  expected_code: string;
}

type ObservationField = "state" | "claim_counts" | "receipt_writes";

type TraceStep =
  | { operation: "verify_fixture"; fixture: "positive_chain" | "positive_not_dispatched" }
  | { operation: "verify_transaction" }
  | { operation: "register_grant"; document?: "primary" | "secondary" }
  | { operation: "prepare_conflicting_grant"; uniqueness: "decision" | "proposal" }
  | {
      operation: "claim_grant";
      attempt_id: string;
      now: { source: "receipt_claimed_at" | "grant_not_before" | "grant_expires_at"; offset_ms?: number };
      repeat?: number;
      request_overrides?: Partial<ClaimRequest>;
      allowed_error?: string;
      require_error?: boolean;
    }
  | {
      operation: "record_receipt";
      repeat?: number;
      overrides?: JsonObject;
    }
  | {
      operation: "mutate_transaction";
      changes: Array<{ pointer: string; replacement: unknown }>;
    }
  | { operation: "append_terminal_successor" }
  | { operation: "fill_reconciliation_history"; count: "maximum_plus_one" }
  | {
      operation: "parse_transport";
      vector:
        | "duplicate_key"
        | "escaped_duplicate_key"
        | "invalid_utf8"
        | "unescaped_control"
        | "protocol_c1_control"
        | "depth_boundary"
        | "depth_limit"
        | "node_boundary"
        | "node_limit"
        | "byte_limit"
        | "unpaired_surrogate";
    }
  | {
      operation: "canonicalize";
      vector:
        | "object_order"
        | "unicode_scalar_order"
        | "escape_set"
        | "negative_zero"
        | "fraction"
        | "exponent"
        | "unsafe_integer";
    };

interface TraceCase {
  id: string;
  steps: TraceStep[];
  observe?: ObservationField[];
  oracle?: "sequential_lifecycle";
}

interface TraceDocument {
  $schema: string;
  schema_version: number;
  profile: string;
  base: string;
  traces: TraceCase[];
}

interface SuiteContext {
  base: JsonObject;
  notDispatched: JsonObject;
  mutations: Map<string, MutationCase>;
  traces: Map<string, TraceCase>;
}

export interface CaseResult {
  id: string;
  category: string;
  pass: boolean;
  expected: ExpectedObservation;
  actual: ExpectedObservation;
}

export interface ConformanceReport {
  suite: string;
  suite_version: number;
  profile: string;
  implementation: string;
  manifest_sha256: string;
  environment: { node: string; platform: string; arch: string };
  summary: {
    total: number;
    passed: number;
    failed: number;
    categories: Record<string, { total: number; passed: number; failed: number }>;
  };
  success: boolean;
  cases: CaseResult[];
}

class ConformanceError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ConformanceError";
    this.code = code;
  }
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function setPointer(document: unknown, pointer: string, replacement: unknown): void {
  if (!pointer.startsWith("/")) throw new ConformanceError("invalid_vector", pointer);
  const parts = pointer.slice(1).split("/").map((part) =>
    part.replaceAll("~1", "/").replaceAll("~0", "~"));
  let cursor = document as JsonObject;
  for (const part of parts.slice(0, -1)) cursor = cursor[part] as JsonObject;
  cursor[parts.at(-1) as string] = clone(replacement);
}

function digest(pair: string): string {
  return `sha256:${pair.repeat(32)}`;
}

function grantBundle(transaction: JsonObject): JsonObject {
  const result = clone(transaction);
  delete result.receipt;
  delete result.reconciliations;
  return result;
}

interface ClaimRequest {
  attempt_id: string;
  expected_audience: string;
  observed_policy_epoch: number;
  observed_configuration_epoch: number;
  observed_pre_state_digest: string;
  observed_resource_claim_digest: string;
  revoked: boolean;
}

interface StoredGrant {
  bundle: JsonObject;
  grantHash: string;
  claim: { attempt_id: string; claimed_at_ms: number } | null;
  receiptHash: string | null;
  receiptWrites: number;
}

/**
 * Minimal lifecycle target for protocol conformance. Structural validation is
 * delegated to the public verifier; this class only models the stateful
 * registration, currentness, single-use claim, and receipt invariants that a
 * stateless bundle verifier cannot observe.
 */
class ReferenceLifecycleTarget {
  private readonly grants = new Map<string, StoredGrant>();
  private readonly decisions = new Set<string>();
  private readonly proposals = new Set<string>();
  private lastTrustedTime: number | null = null;

  register(bundle: JsonObject): string {
    const verified = verifyTransaction(bundle);
    if (verified.grant_hash === null || bundle.grant === undefined) {
      throw new ConformanceError("missing_grant", "registration requires a grant");
    }
    const grantId = bundle.grant.grant_id as string;
    if (this.grants.has(grantId)) {
      throw new ConformanceError("duplicate_grant", "grant identifier already registered");
    }
    if (this.decisions.has(verified.decision_hash)) {
      throw new ConformanceError("decision_already_granted", "decision already issued a grant");
    }
    if (this.proposals.has(verified.proposal_hash)) {
      throw new ConformanceError("proposal_already_granted", "proposal already issued a grant");
    }
    this.grants.set(grantId, {
      bundle: clone(bundle),
      grantHash: verified.grant_hash,
      claim: null,
      receiptHash: null,
      receiptWrites: 0,
    });
    this.decisions.add(verified.decision_hash);
    this.proposals.add(verified.proposal_hash);
    return verified.grant_hash;
  }

  claim(grantId: string, request: ClaimRequest, nowMs: number | null): void {
    if (nowMs === null) throw new ConformanceError("clock_unavailable", "trusted clock unavailable");
    if (this.lastTrustedTime !== null && nowMs < this.lastTrustedTime) {
      throw new ConformanceError("clock_rollback", "trusted time moved backwards");
    }
    this.lastTrustedTime = nowMs;
    const stored = this.grants.get(grantId);
    if (stored === undefined) throw new ConformanceError("unknown_grant", grantId);
    const { commitment, proposal, grant } = stored.bundle;
    if (request.expected_audience !== grant.audience) {
      throw new ConformanceError("audience_mismatch", "executor audience differs");
    }
    if (
      request.observed_policy_epoch !== commitment.policy_epoch ||
      request.observed_configuration_epoch !== commitment.configuration_epoch
    ) {
      throw new ConformanceError("stale_authority", "authority epoch differs");
    }
    if (request.observed_pre_state_digest !== proposal.pre_state_digest) {
      throw new ConformanceError("stale_pre_state", "target pre-state differs");
    }
    if (request.observed_resource_claim_digest !== proposal.resource_claim_digest) {
      throw new ConformanceError("stale_resource_claim", "resource claim differs");
    }
    if (request.revoked) throw new ConformanceError("grant_revoked", "grant was revoked");
    if (nowMs < grant.not_before_ms) {
      throw new ConformanceError("grant_not_yet_valid", "grant is premature");
    }
    if (nowMs >= grant.expires_at_ms) {
      throw new ConformanceError("grant_expired", "grant expired");
    }
    if (stored.claim !== null) {
      throw new ConformanceError("grant_already_claimed", "grant is single-use");
    }
    stored.claim = { attempt_id: request.attempt_id, claimed_at_ms: nowMs };
  }

  recordReceipt(grantId: string, receipt: JsonObject): string {
    const stored = this.grants.get(grantId);
    if (stored === undefined) throw new ConformanceError("unknown_grant", grantId);
    if (stored.claim === null) {
      throw new ConformanceError("receipt_without_claim", "receipt has no winning claim");
    }
    if (
      receipt.attempt_id !== stored.claim.attempt_id ||
      receipt.claimed_at_ms !== stored.claim.claimed_at_ms
    ) {
      throw new ConformanceError("receipt_claim_mismatch", "receipt does not match winning claim");
    }
    const candidate = clone(stored.bundle);
    candidate.receipt = clone(receipt);
    const verified = verifyTransaction(candidate);
    const receiptHash = verified.receipt_hash as string;
    if (stored.receiptHash !== null) {
      if (stored.receiptHash === receiptHash) return receiptHash;
      throw new ConformanceError("receipt_already_recorded", "a conflicting receipt exists");
    }
    stored.receiptHash = receiptHash;
    stored.receiptWrites += 1;
    return receiptHash;
  }

  receiptWrites(grantId: string): number {
    return this.grants.get(grantId)?.receiptWrites ?? 0;
  }
}

function claimRequest(transaction: JsonObject, attemptId = "attempt-01"): ClaimRequest {
  return {
    attempt_id: attemptId,
    expected_audience: transaction.grant.audience,
    observed_policy_epoch: transaction.commitment.policy_epoch,
    observed_configuration_epoch: transaction.commitment.configuration_epoch,
    observed_pre_state_digest: transaction.proposal.pre_state_digest,
    observed_resource_claim_digest: transaction.proposal.resource_claim_digest,
    revoked: false,
  };
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ConformanceError("invalid_utf8", "transport is not valid UTF-8");
  }
}

function accepted(extra: Omit<ExpectedObservation, "verdict"> = {}): ExpectedObservation {
  return { verdict: "accept", ...extra };
}

function rejected(error: unknown, extra: Omit<ExpectedObservation, "verdict" | "code"> = {}): ExpectedObservation {
  if (
    error instanceof VerificationError ||
    error instanceof CanonicalizationError ||
    error instanceof ConformanceError
  ) {
    return { verdict: "reject", code: error.code, ...extra };
  }
  return { verdict: "reject", code: "unexpected_error", ...extra };
}

interface TraceState {
  transaction: JsonObject;
  secondary: JsonObject | null;
  target: ReferenceLifecycleTarget;
  state: string | null;
  canonical: string | null;
  successfulClaims: number;
  rejectedClaims: number;
}

function traceObservation(trace: TraceCase, state: TraceState): Omit<ExpectedObservation, "verdict" | "code"> {
  const observation: Omit<ExpectedObservation, "verdict" | "code"> = {};
  for (const field of trace.observe ?? []) {
    if (field === "state" && state.state !== null) observation.state = state.state;
    if (field === "claim_counts") {
      observation.successful_claims = state.successfulClaims;
      observation.rejected_claims = state.rejectedClaims;
    }
    if (field === "receipt_writes") {
      observation.receipt_writes = state.target.receiptWrites(state.transaction.grant.grant_id);
    }
  }
  if (state.canonical !== null) observation.canonical = state.canonical;
  return observation;
}

function trustedTime(transaction: JsonObject, now: Extract<TraceStep, { operation: "claim_grant" }>["now"]): number {
  const offset = now.offset_ms ?? 0;
  if (now.source === "receipt_claimed_at") return (transaction.receipt.claimed_at_ms as number) + offset;
  if (now.source === "grant_not_before") return (transaction.grant.not_before_ms as number) + offset;
  return (transaction.grant.expires_at_ms as number) + offset;
}

function executeTransportVector(vector: Extract<TraceStep, { operation: "parse_transport" }>["vector"], transaction: JsonObject): void {
  if (vector === "duplicate_key") parseStrictJson('{"a":1,"a":2}');
  else if (vector === "escaped_duplicate_key") parseStrictJson('{"a":1,"\\u0061":2}');
  else if (vector === "invalid_utf8") {
    parseStrictJson(decodeUtf8(Uint8Array.of(0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d)));
  } else if (vector === "unescaped_control") parseStrictJson('{"x":"line\nfeed"}');
  else if (vector === "protocol_c1_control") {
    transaction.commitment.principal = "principal\u0085name";
    verifyTransaction(parseStrictJson(JSON.stringify(transaction)));
  } else if (vector === "depth_boundary" || vector === "depth_limit") {
    const depth = MAX_TRANSPORT_NESTING_DEPTH - (vector === "depth_boundary" ? 1 : 0);
    parseStrictJson("[".repeat(depth) + "null" + "]".repeat(depth));
  } else if (vector === "node_boundary" || vector === "node_limit") {
    const nodes = MAX_TRANSPORT_NODES - (vector === "node_boundary" ? 1 : 0);
    parseStrictJson(`[${Array.from({ length: nodes }, () => "null").join(",")}]`);
  } else if (vector === "byte_limit") {
    parseStrictJson(`"${"a".repeat(MAX_TRANSPORT_INPUT_BYTES)}"`);
  } else {
    parseStrictJson('{"bad":"\\ud800"}');
  }
}

function executeCanonicalVector(
  vector: Extract<TraceStep, { operation: "canonicalize" }>["vector"],
): string | null {
  if (vector === "object_order") return canonicalJson({ z: 1, a: 2 });
  if (vector === "unicode_scalar_order") return canonicalJson({ "😀": 1, "é": 2 });
  if (vector === "escape_set") return canonicalJson("line\n\t\b\f\r\"\\");
  if (vector === "negative_zero") canonicalJson(-0);
  else if (vector === "fraction") parseStrictJson("1.5");
  else if (vector === "exponent") parseStrictJson("1e3");
  else parseStrictJson("9007199254740992");
  return null;
}

function executeTraceStep(step: TraceStep, state: TraceState, context: SuiteContext): void {
  switch (step.operation) {
    case "verify_fixture": {
      state.transaction = clone(
        step.fixture === "positive_chain" ? context.base.transaction : context.notDispatched.transaction,
      );
      state.state = verifyTransaction(state.transaction).state;
      return;
    }
    case "verify_transaction":
      state.state = verifyTransaction(state.transaction).state;
      return;
    case "register_grant": {
      const document = step.document === "secondary" ? state.secondary : grantBundle(state.transaction);
      if (document === null) throw new ConformanceError("invalid_trace", "secondary grant is not prepared");
      state.target.register(document);
      return;
    }
    case "prepare_conflicting_grant": {
      const second = grantBundle(state.transaction);
      second.grant.grant_id = "grant-02";
      second.grant.nonce = "8f9a99c1AQIDBAUGBwgJCg";
      if (step.uniqueness === "proposal") {
        second.decision.decision_id = "decision-02";
        second.decision.reason_codes = ["policy.second-evaluation"];
        second.grant.decision_hash = hashAuthorizationDecision(second.decision);
      }
      state.secondary = second;
      return;
    }
    case "claim_grant": {
      const repeat = step.repeat ?? 1;
      for (let index = 0; index < repeat; index += 1) {
        const attemptId = step.attempt_id.replaceAll("{index}", String(index));
        const request = { ...claimRequest(state.transaction, attemptId), ...(step.request_overrides ?? {}) };
        let observedError = false;
        try {
          state.target.claim(
            state.transaction.grant.grant_id,
            request,
            trustedTime(state.transaction, step.now),
          );
          state.successfulClaims += 1;
        } catch (error) {
          if (
            step.allowed_error === undefined ||
            !(error instanceof ConformanceError) ||
            error.code !== step.allowed_error
          ) throw error;
          state.rejectedClaims += 1;
          observedError = true;
        }
        if (step.require_error === true && !observedError) {
          throw new ConformanceError("expected_error_not_observed", step.allowed_error ?? "unspecified");
        }
      }
      return;
    }
    case "record_receipt": {
      const receipt = { ...clone(state.transaction.receipt), ...(step.overrides ?? {}) };
      for (let index = 0; index < (step.repeat ?? 1); index += 1) {
        state.target.recordReceipt(state.transaction.grant.grant_id, receipt);
      }
      return;
    }
    case "mutate_transaction":
      for (const change of step.changes) setPointer(state.transaction, change.pointer, change.replacement);
      return;
    case "append_terminal_successor": {
      const terminal = state.transaction.reconciliations.at(-1);
      state.transaction.reconciliations.push({
        version: 1,
        reconciliation_id: "reconciliation-03",
        receipt_hash: terminal.receipt_hash,
        sequence: terminal.sequence + 1,
        parent_reconciliation_hash: hashReconciliationRecord(terminal),
        observed_at_ms: terminal.observed_at_ms + 1,
        outcome: "still_unknown",
        evidence_digest: digest("dd"),
      });
      return;
    }
    case "fill_reconciliation_history":
      state.transaction.reconciliations = Array.from(
        { length: MAX_RECONCILIATION_RECORDS + 1 },
        () => null,
      );
      return;
    case "parse_transport":
      executeTransportVector(step.vector, state.transaction);
      return;
    case "canonicalize":
      state.canonical = executeCanonicalVector(step.vector);
      return;
  }
}

function executeTrace(trace: TraceCase, context: SuiteContext): ExpectedObservation {
  const state: TraceState = {
    transaction: clone(context.base.transaction),
    secondary: null,
    target: new ReferenceLifecycleTarget(),
    state: null,
    canonical: null,
    successfulClaims: 0,
    rejectedClaims: 0,
  };
  try {
    for (const step of trace.steps) executeTraceStep(step, state, context);
    return accepted(traceObservation(trace, state));
  } catch (error) {
    return rejected(error, traceObservation(trace, state));
  }
}

async function executeCase(id: string, context: SuiteContext): Promise<ExpectedObservation> {
  const mutation = context.mutations.get(id);
  if (mutation !== undefined) {
    const transaction = clone(context.base.transaction);
    setPointer(transaction, mutation.pointer, mutation.replacement);
    for (const additional of mutation.also ?? []) {
      setPointer(transaction, additional.pointer, additional.replacement);
    }
    return accepted({ state: verifyTransaction(transaction).state });
  }
  const trace = context.traces.get(id);
  if (trace === undefined) throw new ConformanceError("unknown_case", `no trace for ${id}`);
  return executeTrace(trace, context);
}

function matchesExpected(actual: ExpectedObservation, expected: ExpectedObservation): boolean {
  return Object.entries(expected).every(([key, value]) =>
    (actual as Record<string, unknown>)[key] === value);
}

async function loadStrict(url: URL): Promise<{ raw: string; value: unknown }> {
  const bytes = await readFile(url);
  const raw = decodeUtf8(bytes);
  return { raw, value: parseStrictJson(raw) };
}

function requireObject(value: unknown, path: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConformanceError("invalid_trace", `${path} must be an object`);
  }
  return value as JsonObject;
}

function requireExactKeys(
  value: JsonObject,
  path: string,
  required: string[],
  optional: string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new ConformanceError("invalid_trace", `${path}.${key} is required`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new ConformanceError("invalid_trace", `${path}.${key} is not allowed`);
  }
}

function requireString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ConformanceError("invalid_trace", `${path} must be a non-empty string`);
  }
  return value;
}

function requireEnum<T extends string>(value: unknown, path: string, allowed: readonly T[]): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new ConformanceError("invalid_trace", `${path} is not a supported value`);
  }
  return value as T;
}

function validateTraceStep(value: unknown, path: string): TraceStep {
  const step = requireObject(value, path);
  const operation = requireString(step.operation, `${path}.operation`);
  if (operation === "verify_fixture") {
    requireExactKeys(step, path, ["operation", "fixture"]);
    requireEnum(step.fixture, `${path}.fixture`, ["positive_chain", "positive_not_dispatched"]);
  } else if (operation === "verify_transaction") {
    requireExactKeys(step, path, ["operation"]);
  } else if (operation === "register_grant") {
    requireExactKeys(step, path, ["operation"], ["document"]);
    if (step.document !== undefined) requireEnum(step.document, `${path}.document`, ["primary", "secondary"]);
  } else if (operation === "prepare_conflicting_grant") {
    requireExactKeys(step, path, ["operation", "uniqueness"]);
    requireEnum(step.uniqueness, `${path}.uniqueness`, ["decision", "proposal"]);
  } else if (operation === "claim_grant") {
    requireExactKeys(
      step,
      path,
      ["operation", "attempt_id", "now"],
      ["repeat", "request_overrides", "allowed_error", "require_error"],
    );
    requireString(step.attempt_id, `${path}.attempt_id`);
    const now = requireObject(step.now, `${path}.now`);
    requireExactKeys(now, `${path}.now`, ["source"], ["offset_ms"]);
    requireEnum(now.source, `${path}.now.source`, [
      "receipt_claimed_at", "grant_not_before", "grant_expires_at",
    ]);
    if (now.offset_ms !== undefined && !Number.isSafeInteger(now.offset_ms)) {
      throw new ConformanceError("invalid_trace", `${path}.now.offset_ms must be a safe integer`);
    }
    if (step.repeat !== undefined && (!Number.isSafeInteger(step.repeat) || step.repeat < 1 || step.repeat > 64)) {
      throw new ConformanceError("invalid_trace", `${path}.repeat must be an integer from 1 to 64`);
    }
    if (step.allowed_error !== undefined) requireString(step.allowed_error, `${path}.allowed_error`);
    if (step.require_error !== undefined && typeof step.require_error !== "boolean") {
      throw new ConformanceError("invalid_trace", `${path}.require_error must be boolean`);
    }
    if (step.require_error === true && step.allowed_error === undefined) {
      throw new ConformanceError("invalid_trace", `${path}.require_error needs allowed_error`);
    }
    if (step.request_overrides !== undefined) {
      const overrides = requireObject(step.request_overrides, `${path}.request_overrides`);
      requireExactKeys(overrides, `${path}.request_overrides`, [], [
        "attempt_id", "expected_audience", "observed_policy_epoch",
        "observed_configuration_epoch", "observed_pre_state_digest",
        "observed_resource_claim_digest", "revoked",
      ]);
      for (const [key, item] of Object.entries(overrides)) {
        if (["observed_policy_epoch", "observed_configuration_epoch"].includes(key)) {
          if (!Number.isSafeInteger(item)) throw new ConformanceError("invalid_trace", `${path}.${key} must be integer`);
        } else if (key === "revoked") {
          if (typeof item !== "boolean") throw new ConformanceError("invalid_trace", `${path}.${key} must be boolean`);
        } else requireString(item, `${path}.${key}`);
      }
    }
  } else if (operation === "record_receipt") {
    requireExactKeys(step, path, ["operation"], ["repeat", "overrides"]);
    if (step.repeat !== undefined && (!Number.isSafeInteger(step.repeat) || step.repeat < 1 || step.repeat > 64)) {
      throw new ConformanceError("invalid_trace", `${path}.repeat must be an integer from 1 to 64`);
    }
    if (step.overrides !== undefined) {
      const overrides = requireObject(step.overrides, `${path}.overrides`);
      requireExactKeys(overrides, `${path}.overrides`, [], ["attempt_id", "observation_digest"]);
      for (const [key, item] of Object.entries(overrides)) requireString(item, `${path}.${key}`);
    }
  } else if (operation === "mutate_transaction") {
    requireExactKeys(step, path, ["operation", "changes"]);
    if (!Array.isArray(step.changes) || step.changes.length === 0 || step.changes.length > 16) {
      throw new ConformanceError("invalid_trace", `${path}.changes must contain 1 to 16 entries`);
    }
    for (const [index, item] of step.changes.entries()) {
      const change = requireObject(item, `${path}.changes[${index}]`);
      requireExactKeys(change, `${path}.changes[${index}]`, ["pointer", "replacement"]);
      const pointer = requireString(change.pointer, `${path}.changes[${index}].pointer`);
      if (!pointer.startsWith("/")) throw new ConformanceError("invalid_trace", `${path}.changes[${index}].pointer`);
    }
  } else if (operation === "append_terminal_successor") {
    requireExactKeys(step, path, ["operation"]);
  } else if (operation === "fill_reconciliation_history") {
    requireExactKeys(step, path, ["operation", "count"]);
    requireEnum(step.count, `${path}.count`, ["maximum_plus_one"]);
  } else if (operation === "parse_transport") {
    requireExactKeys(step, path, ["operation", "vector"]);
    requireEnum(step.vector, `${path}.vector`, [
      "duplicate_key", "escaped_duplicate_key", "invalid_utf8", "unescaped_control",
      "protocol_c1_control", "depth_boundary", "depth_limit", "node_boundary",
      "node_limit", "byte_limit", "unpaired_surrogate",
    ]);
  } else if (operation === "canonicalize") {
    requireExactKeys(step, path, ["operation", "vector"]);
    requireEnum(step.vector, `${path}.vector`, [
      "object_order", "unicode_scalar_order", "escape_set", "negative_zero",
      "fraction", "exponent", "unsafe_integer",
    ]);
  } else {
    throw new ConformanceError("invalid_trace", `${path}.operation is unknown`);
  }
  return step as TraceStep;
}

function validateTraceDocument(value: unknown): TraceDocument {
  const document = requireObject(value, "traces");
  requireExactKeys(document, "traces", ["$schema", "schema_version", "profile", "base", "traces"]);
  requireString(document.$schema, "traces.$schema");
  if (document.schema_version !== 1) throw new ConformanceError("invalid_trace", "unsupported trace schema");
  requireString(document.profile, "traces.profile");
  requireString(document.base, "traces.base");
  if (!Array.isArray(document.traces) || document.traces.length === 0) {
    throw new ConformanceError("invalid_trace", "traces.traces must be a non-empty array");
  }
  const ids = new Set<string>();
  const traces = document.traces.map((value: unknown, index: number): TraceCase => {
    const path = `traces.traces[${index}]`;
    const trace = requireObject(value, path);
    requireExactKeys(trace, path, ["id", "steps"], ["observe", "oracle"]);
    const id = requireString(trace.id, `${path}.id`);
    if (ids.has(id)) throw new ConformanceError("invalid_trace", `duplicate trace ${id}`);
    ids.add(id);
    if (!Array.isArray(trace.steps) || trace.steps.length === 0 || trace.steps.length > 32) {
      throw new ConformanceError("invalid_trace", `${path}.steps must contain 1 to 32 operations`);
    }
    const steps = trace.steps.map((step: unknown, stepIndex: number) =>
      validateTraceStep(step, `${path}.steps[${stepIndex}]`));
    let observe: ObservationField[] | undefined;
    if (trace.observe !== undefined) {
      if (!Array.isArray(trace.observe) || new Set(trace.observe).size !== trace.observe.length) {
        throw new ConformanceError("invalid_trace", `${path}.observe must contain unique values`);
      }
      observe = trace.observe.map((item: unknown, itemIndex: number) =>
        requireEnum(item, `${path}.observe[${itemIndex}]`, ["state", "claim_counts", "receipt_writes"]));
    }
    let oracle: "sequential_lifecycle" | undefined;
    if (trace.oracle !== undefined) {
      oracle = requireEnum(trace.oracle, `${path}.oracle`, ["sequential_lifecycle"]);
    }
    if (steps.some((step) => step.operation === "claim_grant" && (step.repeat ?? 1) > 1) && oracle === undefined) {
      throw new ConformanceError("invalid_trace", `${path} must identify its sequential oracle`);
    }
    return { id, steps, ...(observe === undefined ? {} : { observe }), ...(oracle === undefined ? {} : { oracle }) };
  });
  return {
    $schema: document.$schema as string,
    schema_version: 1,
    profile: document.profile as string,
    base: document.base as string,
    traces,
  };
}

async function loadContext(traceUrl: URL): Promise<SuiteContext> {
  const base = (await loadStrict(new URL("../vectors/positive-chain.json", import.meta.url))).value as JsonObject;
  const notDispatched = (
    await loadStrict(new URL("../vectors/positive-not-dispatched.json", import.meta.url))
  ).value as JsonObject;
  const mutationDocument = (
    await loadStrict(new URL("../vectors/conformance-mutations.json", import.meta.url))
  ).value as { cases: MutationCase[] };
  const mutations = new Map<string, MutationCase>();
  for (const mutation of mutationDocument.cases) {
    if (mutations.has(mutation.id)) throw new ConformanceError("invalid_vector", mutation.id);
    mutations.set(mutation.id, mutation);
  }
  const traceDocument = validateTraceDocument((await loadStrict(traceUrl)).value);
  if (traceDocument.profile !== "effect-transaction/core/0.1") {
    throw new ConformanceError("invalid_trace", `unsupported trace profile ${traceDocument.profile}`);
  }
  if (traceDocument.base !== "positive-chain.json") {
    throw new ConformanceError("invalid_trace", `unsupported trace base ${traceDocument.base}`);
  }
  const traces = new Map(traceDocument.traces.map((trace) => [trace.id, trace]));
  return { base, notDispatched, mutations, traces };
}

export async function runConformanceSuite(
  manifestUrl = new URL("./manifest.json", import.meta.url),
  traceUrl = new URL("../vectors/conformance-traces.json", import.meta.url),
): Promise<ConformanceReport> {
  const loaded = await loadStrict(manifestUrl);
  const manifest = loaded.value as Manifest;
  const ids = new Set<string>();
  for (const entry of manifest.cases) {
    if (ids.has(entry.id)) throw new ConformanceError("invalid_manifest", `duplicate case ${entry.id}`);
    ids.add(entry.id);
  }
  const context = await loadContext(traceUrl);
  if (manifest.profile !== "effect-transaction/core/0.1") {
    throw new ConformanceError("invalid_manifest", `unsupported profile ${manifest.profile}`);
  }
  for (const [id, mutation] of context.mutations) {
    const declared = manifest.cases.find((entry) => entry.id === id);
    if (declared === undefined) {
      throw new ConformanceError("invalid_manifest", `mutation case is not declared: ${id}`);
    }
    if (declared.expected.verdict !== "reject" || declared.expected.code !== mutation.expected_code) {
      throw new ConformanceError(
        "invalid_manifest",
        `mutation expectation differs between manifest and vector: ${id}`,
      );
    }
  }
  for (const [id] of context.traces) {
    if (!ids.has(id)) throw new ConformanceError("invalid_manifest", `trace is not declared: ${id}`);
    if (context.mutations.has(id)) throw new ConformanceError("invalid_manifest", `case has trace and mutation: ${id}`);
  }
  for (const id of ids) {
    if (!context.mutations.has(id) && !context.traces.has(id)) {
      throw new ConformanceError("invalid_manifest", `case has no mutation or trace: ${id}`);
    }
  }
  const cases: CaseResult[] = [];
  for (const entry of manifest.cases) {
    let actual: ExpectedObservation;
    try {
      actual = await executeCase(entry.id, context);
    } catch (error) {
      actual = rejected(error);
    }
    cases.push({
      id: entry.id,
      category: entry.category,
      pass: matchesExpected(actual, entry.expected),
      expected: entry.expected,
      actual,
    });
  }
  const categories: Record<string, { total: number; passed: number; failed: number }> = {};
  for (const result of cases) {
    categories[result.category] ??= { total: 0, passed: 0, failed: 0 };
    categories[result.category].total += 1;
    categories[result.category][result.pass ? "passed" : "failed"] += 1;
  }
  const passed = cases.filter((entry) => entry.pass).length;
  return {
    suite: manifest.suite,
    suite_version: manifest.suite_version,
    profile: manifest.profile,
    implementation: "@effect-transaction/verifier@0.1.0-alpha.1",
    manifest_sha256: createHash("sha256").update(loaded.raw, "utf8").digest("hex"),
    environment: { node: process.version, platform: process.platform, arch: process.arch },
    summary: {
      total: cases.length,
      passed,
      failed: cases.length - passed,
      categories,
    },
    success: passed === cases.length,
    cases,
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let manifestUrl = new URL("./manifest.json", import.meta.url);
  let traceUrl = new URL("../vectors/conformance-traces.json", import.meta.url);
  let reportPath: string | null = null;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--manifest" && args[index + 1] !== undefined) {
      manifestUrl = pathToFileURL(resolve(args[index + 1]));
      index += 1;
    } else if (args[index] === "--traces" && args[index + 1] !== undefined) {
      traceUrl = pathToFileURL(resolve(args[index + 1]));
      index += 1;
    } else if (args[index] === "--report" && args[index + 1] !== undefined) {
      reportPath = resolve(args[index + 1]);
      index += 1;
    } else {
      throw new ConformanceError("usage", `unknown or incomplete argument: ${args[index]}`);
    }
  }
  const report = await runConformanceSuite(manifestUrl, traceUrl);
  const json = `${JSON.stringify(report, null, 2)}\n`;
  if (reportPath === null) process.stdout.write(json);
  else await writeFile(reportPath, json, "utf8");
  if (!report.success) process.exitCode = 1;
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error: unknown) => {
    const actual = rejected(error);
    process.stderr.write(`${JSON.stringify({ success: false, error: actual })}\n`);
    process.exitCode = 2;
  });
}

import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { parseStrictJson } from "../src/canonical.ts";
import { unwrapVerificationInput } from "../src/input.ts";
import {
  MAX_RECONCILIATION_RECORDS,
  VerificationError,
  verifyTransaction,
} from "../src/verify.ts";
import { validTransaction } from "./fixtures.ts";

const vectors = fileURLToPath(new URL("../../vectors/", import.meta.url));
const schemas = fileURLToPath(new URL("../../schemas/", import.meta.url));

function clone(value: unknown): unknown {
  return structuredClone(value);
}

function expectCode(value: unknown, code: string): void {
  assert.throws(
    () => verifyTransaction(value),
    (error: unknown) => error instanceof VerificationError && error.code === code,
  );
}

function setPointer(document: unknown, pointer: string, replacement: unknown): void {
  const parts = pointer.slice(1).split("/").map((part) =>
    part.replaceAll("~1", "/").replaceAll("~0", "~"));
  let cursor = document as Record<string, unknown> | unknown[];
  for (const part of parts.slice(0, -1)) {
    cursor = (cursor as Record<string, unknown>)[part] as Record<string, unknown>;
  }
  (cursor as Record<string, unknown>)[parts.at(-1) as string] = replacement;
}

function collectExternalSchemaRefs(value: unknown, refs: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) collectExternalSchemaRefs(item, refs);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (key === "$ref" && typeof item === "string" && !item.startsWith("#")) {
      const [schemaId] = item.split("#", 1);
      refs.add(schemaId);
    }
    collectExternalSchemaRefs(item, refs);
  }
}

function resolveSchemaFragment(document: Record<string, unknown>, fragment: string): unknown {
  if (fragment === "") return document;
  assert.ok(fragment.startsWith("/"), `unsupported schema fragment: #${fragment}`);
  let cursor: unknown = document;
  for (const encodedPart of fragment.slice(1).split("/")) {
    const part = decodeURIComponent(encodedPart).replaceAll("~1", "/").replaceAll("~0", "~");
    assert.ok(cursor !== null && typeof cursor === "object" && !Array.isArray(cursor));
    assert.ok(Object.hasOwn(cursor, part), `unresolved schema fragment: #${fragment}`);
    cursor = (cursor as Record<string, unknown>)[part];
  }
  return cursor;
}

test("valid in-memory chain exposes the terminal reconciliation outcome", () => {
  const result = verifyTransaction(validTransaction());
  assert.equal(result.state, "effect_confirmed");
  assert.equal(result.reconciliation_hashes.length, 2);
});

test("protocol text rejects C1 control characters", () => {
  const bundle = validTransaction();
  bundle.commitment.principal = "principal\u0085name";
  assert.throws(
    () => verifyTransaction(bundle),
    (error: unknown) => error instanceof VerificationError && error.code === "control_character",
  );
});

test("field limits count UTF-8 bytes, not Unicode scalar values", () => {
  const bundle = validTransaction();
  bundle.commitment.commitment_id = "é".repeat(256);
  assert.equal([...bundle.commitment.commitment_id].length, 256);
  assert.equal(Buffer.byteLength(bundle.commitment.commitment_id, "utf8"), 512);
  expectCode(bundle, "string_length");
});

test("a non-allow decision cannot produce a grant", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  value.decision.outcome = "deny";
  expectCode(value, "nonauthorizing_decision");
});

test("reconciliations is an array before grant issuance", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  delete value.grant;
  delete value.receipt;
  value.reconciliations = "not-an-array";
  expectCode(value, "array");
});

test("invalid use count and predecessor links are rejected", () => {
  const multipleUses = clone(validTransaction()) as Record<string, any>;
  multipleUses.grant.uses = 2;
  expectCode(multipleUses, "single_use");

  const substituted = clone(validTransaction()) as Record<string, any>;
  substituted.proposal.commitment_hash = `sha256:${"d0".repeat(32)}`;
  expectCode(substituted, "binding_mismatch");
});

test("heterogeneous identifier fields use independent namespaces", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  value.receipt.attempt_id = value.grant.grant_id;
  value.reconciliations = [];
  assert.equal(verifyTransaction(value).state, "unknown");
});

test("reconciliation identifiers cannot repeat within one chain", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  value.reconciliations[1].reconciliation_id = value.reconciliations[0].reconciliation_id;
  expectCode(value, "duplicate_identifier");
});

test("grant lifetime is capped at five minutes", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  value.grant.expires_at_ms = value.grant.not_before_ms + 300_001;
  expectCode(value, "grant_lifetime");
});

test("unknown receipts cannot be claimed after grant expiry", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  value.receipt.claimed_at_ms = value.grant.expires_at_ms;
  value.receipt.dispatched_at_ms = value.grant.expires_at_ms + 100;
  value.receipt.completed_at_ms = value.grant.expires_at_ms + 200;
  expectCode(value, "expired_claim");
});

test("pre-dispatch recovery produces a not_dispatched receipt", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  value.receipt.outcome = "not_dispatched";
  value.receipt.dispatched_at_ms = null;
  value.reconciliations = [];
  assert.equal(verifyTransaction(value).state, "not_dispatched");
});

test("unknown permits both dispatch timestamp forms", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  value.receipt.dispatched_at_ms = null;
  value.reconciliations = [];
  assert.equal(verifyTransaction(value).state, "unknown");
});

test("receipt outcome and dispatch evidence must agree", () => {
  const falseSuccess = clone(validTransaction()) as Record<string, any>;
  falseSuccess.receipt.outcome = "succeeded";
  falseSuccess.receipt.dispatched_at_ms = null;
  expectCode(falseSuccess, "receipt_dispatch");

  const falseNonDispatch = clone(validTransaction()) as Record<string, any>;
  falseNonDispatch.receipt.outcome = "not_dispatched";
  expectCode(falseNonDispatch, "receipt_dispatch");
});

test("reconciliation list has a hard verification budget", () => {
  const value = clone(validTransaction()) as Record<string, any>;
  value.reconciliations = Array.from(
    { length: MAX_RECONCILIATION_RECORDS + 1 },
    () => null,
  );
  expectCode(value, "array_length");
});

test("positive vector produces the expected commitments", async () => {
  const raw = await readFile(`${vectors}positive-chain.json`, "utf8");
  const vector = parseStrictJson(raw) as Record<string, unknown>;
  const result = verifyTransaction(vector.transaction);
  assert.deepEqual(result, vector.expected);
});

test("lifecycle bundles and test-vector envelopes are distinct", async () => {
  const raw = await readFile(`${vectors}positive-chain.json`, "utf8");
  const vector = parseStrictJson(raw) as Record<string, unknown>;
  const wrapped = unwrapVerificationInput(vector);
  assert.deepEqual(verifyTransaction(wrapped.transaction), wrapped.expected);

  const bare = unwrapVerificationInput(vector.transaction);
  assert.equal(bare.expected, null);
  assert.deepEqual(verifyTransaction(bare.transaction), vector.expected);

  const missingExpected = structuredClone(vector);
  delete missingExpected.expected;
  assert.throws(
    () => unwrapVerificationInput(missingExpected),
    (error: unknown) => error instanceof VerificationError && error.code === "missing_field",
  );

  const unknownMetadata = { ...vector, model_comment: "not part of the vector contract" };
  assert.throws(
    () => unwrapVerificationInput(unknownMetadata),
    (error: unknown) => error instanceof VerificationError && error.code === "unknown_field",
  );

  const wrongProfile = { ...vector, profile: "effect-transaction/core/9.9" };
  assert.throws(
    () => unwrapVerificationInput(wrongProfile),
    (error: unknown) => error instanceof VerificationError && error.code === "unsupported_profile",
  );
});

test("schema references resolve from versioned HTTPS identifiers", async () => {
  const files = (await readdir(schemas)).filter((name) => name.endsWith(".schema.json"));
  const documents = await Promise.all(files.map(async (name) =>
    parseStrictJson(await readFile(`${schemas}${name}`, "utf8")) as Record<string, unknown>));
  const registry = new Map(documents.map((document) => [document.$id, document]));
  assert.equal(registry.size, documents.length, "every schema must have one unique $id");

  const refs = new Set<string>();
  for (const document of documents) collectExternalSchemaRefs(document, refs);
  for (const ref of refs) {
    assert.match(ref, /^https:\/\/billmedj\.github\.io\/etp\/schemas\/[a-z0-9-]+-0\.1\.schema\.json(?:#.*)?$/u);
    const [base, fragment = ""] = ref.split("#", 2);
    const target = registry.get(base);
    assert.ok(target, `unresolved schema identifier: ${ref}`);
    resolveSchemaFragment(target, fragment);
  }

  const lifecycle = documents.find((document) =>
    document.$id === "https://billmedj.github.io/etp/schemas/transaction-bundle-0.1.schema.json");
  const envelope = documents.find((document) =>
    document.$id === "https://billmedj.github.io/etp/schemas/test-vector-envelope-0.1.schema.json");
  assert.deepEqual(lifecycle?.required, ["commitment", "proposal", "decision"]);
  assert.deepEqual(envelope?.required, ["profile", "transaction", "expected"]);
});

test("pre-dispatch vector produces the expected receipt commitment", async () => {
  const raw = await readFile(`${vectors}positive-not-dispatched.json`, "utf8");
  const vector = parseStrictJson(raw) as Record<string, unknown>;
  const result = verifyTransaction(vector.transaction);
  assert.deepEqual(result, vector.expected);
});

test("adversarial vectors return the expected reason code", async () => {
  const positive = parseStrictJson(
    await readFile(`${vectors}positive-chain.json`, "utf8"),
  ) as Record<string, unknown>;
  const negative = parseStrictJson(
    await readFile(`${vectors}negative-chains.json`, "utf8"),
  ) as { cases: Array<{
    name: string;
    pointer: string;
    replacement: unknown;
    also?: Array<{ pointer: string; replacement: unknown }>;
    expected_code: string;
  }> };
  for (const vector of negative.cases) {
    const transaction = clone(positive.transaction);
    setPointer(transaction, vector.pointer, vector.replacement);
    for (const mutation of vector.also ?? []) {
      setPointer(transaction, mutation.pointer, mutation.replacement);
    }
    try {
      expectCode(transaction, vector.expected_code);
    } catch (error) {
      throw new Error(`could not evaluate adversarial vector: ${vector.name}`, { cause: error });
    }
  }
});

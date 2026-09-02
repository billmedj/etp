import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  CanonicalizationError,
  MAX_TRANSPORT_INPUT_BYTES,
  MAX_TRANSPORT_NESTING_DEPTH,
  MAX_TRANSPORT_NODES,
  canonicalJson,
  commitment,
  parseStrictJson,
} from "../src/canonical.ts";

test("canonical JSON ignores object insertion order and preserves array order", () => {
  assert.equal(
    canonicalJson({ z: [2, 1], a: { c: true, b: null } }),
    '{"a":{"b":null,"c":true},"z":[2,1]}',
  );
  assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
});

test("canonical strings use the specified short escapes and preserve valid Unicode", () => {
  assert.equal(canonicalJson("line\n\"é"), '"line\\n\\\"é"');
  assert.equal(canonicalJson({ "😀": 1, "é": 2 }), '{"é":2,"😀":1}');
});

test("invalid numbers and non-JSON values are rejected", () => {
  for (const value of [1.5, -0, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, undefined]) {
    assert.throws(() => canonicalJson(value), CanonicalizationError);
  }
  assert.throws(() => canonicalJson("\ud800"), CanonicalizationError);
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), CanonicalizationError);
});

test("in-memory canonicalization enforces depth and node budgets", () => {
  let nested: unknown = null;
  for (let index = 0; index < MAX_TRANSPORT_NESTING_DEPTH; index += 1) nested = [nested];
  assert.throws(
    () => canonicalJson(nested),
    (error: unknown) => error instanceof CanonicalizationError && error.code === "resource_limit",
  );
  const oversized = Array.from({ length: MAX_TRANSPORT_NODES }, () => null);
  assert.throws(
    () => canonicalJson(oversized),
    (error: unknown) => error instanceof CanonicalizationError && error.code === "resource_limit",
  );
});

test("strict transport parser rejects non-integer number syntax", () => {
  for (const text of ['{"n":1.0}', '{"n":1e3}', '{"n":-0}']) {
    assert.throws(() => parseStrictJson(text), CanonicalizationError);
  }
  assert.deepEqual(parseStrictJson('{"text":"1e3","n":1000}'), { text: "1e3", n: 1000 });
});

test("strict transport parser rejects duplicate keys", () => {
  assert.throws(
    () => parseStrictJson('{"a":1,"a":2}'),
    (error: unknown) => error instanceof CanonicalizationError && error.code === "duplicate_key",
  );
  assert.throws(
    () => parseStrictJson('{"a":1,"\\u0061":2}'),
    (error: unknown) => error instanceof CanonicalizationError && error.code === "duplicate_key",
  );
});

test("strict transport parser validates escaped Unicode scalars", () => {
  assert.deepEqual(parseStrictJson('{"emoji":"\\ud83d\\ude00"}'), { emoji: "😀" });
  assert.throws(() => parseStrictJson('{"bad":"\\ud800"}'), CanonicalizationError);
  assert.throws(() => parseStrictJson('{"bad":"\\udc00"}'), CanonicalizationError);
});

test("hash commitments are domain separated", () => {
  const value = { a: 1 };
  assert.notEqual(commitment("domain/a", value), commitment("domain/b", value));
  assert.equal(commitment("domain/a", value), commitment("domain/a", { a: 1 }));
});

test("published canonicalization corpus is stable", () => {
  const vector = parseStrictJson(
    readFileSync(new URL("../../vectors/canonicalization.json", import.meta.url), "utf8"),
  ) as { cases: Array<{ name: string; value: unknown; canonical: string }> };
  for (const entry of vector.cases) {
    assert.equal(canonicalJson(entry.value), entry.canonical, entry.name);
  }
});

test("transport parser enforces its default byte budget", () => {
  const oversized = `"${"a".repeat(MAX_TRANSPORT_INPUT_BYTES)}"`;
  assert.throws(
    () => parseStrictJson(oversized),
    (error: unknown) => error instanceof CanonicalizationError && error.code === "transport_limit",
  );
});

test("transport parser enforces its default nesting budget", () => {
  const oversized = "[".repeat(MAX_TRANSPORT_NESTING_DEPTH + 1) + "null" +
    "]".repeat(MAX_TRANSPORT_NESTING_DEPTH + 1);
  assert.throws(
    () => parseStrictJson(oversized),
    (error: unknown) => error instanceof CanonicalizationError && error.code === "transport_limit",
  );
});

test("transport depth counts the terminal value like the Rust verifier", () => {
  const maximum = "[".repeat(MAX_TRANSPORT_NESTING_DEPTH - 1) + "null" +
    "]".repeat(MAX_TRANSPORT_NESTING_DEPTH - 1);
  assert.equal(parseStrictJson(maximum) !== undefined, true);
  const oversized = "[".repeat(MAX_TRANSPORT_NESTING_DEPTH) + "null" +
    "]".repeat(MAX_TRANSPORT_NESTING_DEPTH);
  assert.throws(
    () => parseStrictJson(oversized),
    (error: unknown) => error instanceof CanonicalizationError && error.code === "transport_limit",
  );
});

test("transport parser enforces its default node budget", () => {
  const oversized = `[${Array.from({ length: MAX_TRANSPORT_NODES }, () => "null").join(",")}]`;
  assert.throws(
    () => parseStrictJson(oversized),
    (error: unknown) => error instanceof CanonicalizationError && error.code === "transport_limit",
  );
});

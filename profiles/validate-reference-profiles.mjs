#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDirectory = join(here, "..", "vectors", "profiles");

class ProfileError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ProfileError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new ProfileError(code, message);
}

function assert(condition, code, message) {
  if (!condition) fail(code, message);
}

function readJson(path) {
  return parseJsonWithoutDuplicateKeys(readFileSync(path, "utf8"));
}

function parseJsonWithoutDuplicateKeys(source) {
  const parsed = JSON.parse(source);
  let index = 0;
  let nodes = 0;

  function skipWhitespace() {
    while (/[\x20\t\r\n]/u.test(source[index] ?? "")) index += 1;
  }

  function stringToken() {
    const start = index;
    assert(source[index] === '"', "PROFILE_JSON", "expected a JSON string");
    index += 1;
    while (index < source.length) {
      if (source[index] === "\\") {
        index += 2;
      } else if (source[index] === '"') {
        index += 1;
        return JSON.parse(source.slice(start, index));
      } else {
        index += 1;
      }
    }
    fail("PROFILE_JSON", "unterminated JSON string");
  }

  function value(depth) {
    nodes += 1;
    assert(depth <= 64 && nodes <= 100_000, "PROFILE_JSON_LIMIT", "JSON structure exceeds profile limits");
    skipWhitespace();
    if (source[index] === "{") return object(depth);
    if (source[index] === "[") return array(depth);
    if (source[index] === '"') {
      stringToken();
      return;
    }
    while (index < source.length && !/[\x20\t\r\n,\]}]/u.test(source[index])) index += 1;
  }

  function object(depth) {
    index += 1;
    skipWhitespace();
    const keys = new Set();
    if (source[index] === "}") {
      index += 1;
      return;
    }
    while (true) {
      const key = stringToken();
      assert(!keys.has(key), "PROFILE_DUPLICATE_KEY", `duplicate JSON key: ${key}`);
      keys.add(key);
      skipWhitespace();
      assert(source[index] === ":", "PROFILE_JSON", "expected ':' after JSON key");
      index += 1;
      value(depth + 1);
      skipWhitespace();
      if (source[index] === "}") {
        index += 1;
        return;
      }
      assert(source[index] === ",", "PROFILE_JSON", "expected ',' between object members");
      index += 1;
      skipWhitespace();
    }
  }

  function array(depth) {
    index += 1;
    skipWhitespace();
    if (source[index] === "]") {
      index += 1;
      return;
    }
    while (true) {
      value(depth + 1);
      skipWhitespace();
      if (source[index] === "]") {
        index += 1;
        return;
      }
      assert(source[index] === ",", "PROFILE_JSON", "expected ',' between array elements");
      index += 1;
    }
  }

  skipWhitespace();
  value(1);
  skipWhitespace();
  assert(index === source.length, "PROFILE_JSON", "unexpected trailing JSON input");
  return parsed;
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function clone(value) {
  return structuredClone(value);
}

function setPath(root, path, value) {
  let cursor = root;
  for (const segment of path.slice(0, -1)) cursor = cursor[segment];
  cursor[path.at(-1)] = clone(value);
}

function applyMutations(base, mutations, profile) {
  const result = clone(base);
  for (const mutation of mutations) {
    if (mutation.op === "set") {
      setPath(result, mutation.path, mutation.value);
      continue;
    }
    if (mutation.op === "set_target_everywhere") {
      result.context.target = mutation.value;
      if (Object.hasOwn(result.documents.pre_state, "target")) result.documents.pre_state.target = mutation.value;
      if (Object.hasOwn(result.documents.resource_claim, "target")) result.documents.resource_claim.target = mutation.value;
      result.documents.dispatch_evidence.target = mutation.value;
      result.documents.observation_evidence.target = mutation.value;
      if (Object.hasOwn(result.documents, "reconciliation_evidence")) {
        result.documents.reconciliation_evidence.target = mutation.value;
      }
      continue;
    }
    if (mutation.op === "rewrite_patch" && profile.includes("kubernetes")) {
      const bytes = Buffer.from(JSON.stringify(mutation.value), "utf8");
      result.documents.arguments.operations = clone(mutation.value);
      result.documents.arguments.patch_utf8_base64url = bytes.toString("base64url");
      result.documents.arguments.patch_sha256 = sha256(bytes);
      continue;
    }
    if (mutation.op === "rewrite_patch_raw" && profile.includes("kubernetes")) {
      const bytes = Buffer.from(mutation.value, "utf8");
      result.documents.arguments.operations = JSON.parse(mutation.value);
      result.documents.arguments.patch_utf8_base64url = bytes.toString("base64url");
      result.documents.arguments.patch_sha256 = sha256(bytes);
      continue;
    }
    fail("VECTOR_MUTATION", `unsupported mutation ${mutation.op}`);
  }
  return result;
}

function exactKeys(value, required, optional, code) {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), code, "expected a document object");
  const allowed = new Set([...required, ...optional]);
  for (const key of required) assert(Object.hasOwn(value, key), code, `missing ${key}`);
  for (const key of Object.keys(value)) assert(allowed.has(key), code, `unknown ${key}`);
}

function envelope(document, profile, type, required, optional = []) {
  exactKeys(document, ["profile", "document_type", "version", ...required], optional, "PROFILE_SCHEMA");
  assert(document.profile === profile, "PROFILE_SCHEMA", "profile identifier mismatch");
  assert(document.document_type === type, "PROFILE_SCHEMA", "document type mismatch");
  assert(document.version === 1, "PROFILE_SCHEMA", "document version mismatch");
}

function validateProfileRegistry(profileFile) {
  const descriptor = readJson(join(here, profileFile));
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    // Conditional branches require properties declared at the closed root.
    // JSON Schema 2020-12 permits this pattern. Disable only Ajv's local check.
    strictRequired: false,
    validateFormats: false,
  });
  const ids = new Set();
  const schemas = new Map();
  for (const [documentType, relativePath] of Object.entries(descriptor.schemas)) {
    const schema = readJson(join(here, relativePath));
    assert(schema.$schema === "https://json-schema.org/draft/2020-12/schema", "PROFILE_SCHEMA_META", `${relativePath} must use JSON Schema 2020-12`);
    assert(typeof schema.$id === "string" && !ids.has(schema.$id), "PROFILE_SCHEMA_META", `${relativePath} has a missing or duplicate $id`);
    ids.add(schema.$id);
    assert(schema.type === "object" && schema.additionalProperties === false, "PROFILE_SCHEMA_META", `${documentType} schema must reject unknown root fields`);
    ajv.addSchema(schema);
    schemas.set(documentType, schema.$id);
  }
  const validators = new Map();
  for (const [documentType, schemaId] of schemas) {
    const validator = ajv.getSchema(schemaId);
    assert(typeof validator === "function", "PROFILE_SCHEMA_META", `schema did not compile: ${schemaId}`);
    validators.set(documentType, validator);
  }
  return validators;
}

function validateDocumentsAgainstSchemas(vector, validators) {
  for (const [documentType, validator] of validators) {
    const document = vector.documents?.[documentType];
    if (documentType === "reconciliation_evidence" && document === undefined) continue;
    assert(document !== undefined, "PROFILE_SCHEMA", `missing ${documentType} document`);
    if (!validator(document)) {
      const detail = (validator.errors ?? [])
        .map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`)
        .join("; ");
      fail("PROFILE_SCHEMA", `${documentType} failed JSON Schema 2020-12 validation: ${detail}`);
    }
  }
}

function validateReceiptLifecycle(vector) {
  exactKeys(vector, ["name", "expected_receipt_outcome", "context", "documents"], [], "VECTOR_SCHEMA");
  assert(
    ["succeeded", "unknown"].includes(vector.expected_receipt_outcome),
    "VECTOR_OUTCOME",
    "expected receipt outcome must be succeeded or unknown",
  );
  const hasReconciliation = Object.hasOwn(vector.documents, "reconciliation_evidence");
  assert(
    (vector.expected_receipt_outcome === "unknown") === hasReconciliation,
    "RECEIPT_LIFECYCLE",
    "reconciliation evidence must be present if and only if the receipt outcome is unknown",
  );
  const transportOutcome = vector.documents.observation_evidence?.transport_outcome;
  if (vector.expected_receipt_outcome === "unknown") {
    assert(
      ["lost", "unverifiable"].includes(transportOutcome),
      "RECEIPT_LIFECYCLE",
      "an unknown receipt requires a lost or unverifiable transport response",
    );
  } else {
    assert(transportOutcome === "response", "RECEIPT_LIFECYCLE", "a succeeded receipt requires a transport response");
  }
}

const forbiddenHttpHeaders = new Set([
  "authorization", "connection", "cookie", "host", "if-match", "if-modified-since",
  "if-none-match", "if-unmodified-since", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "set-cookie", "te", "trailer", "transfer-encoding", "upgrade"
]);

function canonicalHttpTarget(target) {
  assert(typeof target === "string" && target.length <= 4096, "HTTP_TARGET_SYNTAX", "target must be text of 4,096 characters or less");
  assert(!/[\u0000-\u0020\u007f]/u.test(target), "HTTP_TARGET_SYNTAX", "target contains control or space");
  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    fail("HTTP_TARGET_SYNTAX", "target is not an absolute URI");
  }
  assert(parsed.protocol === "https:", "HTTP_TARGET_SCHEME", "target must use https");
  assert(parsed.username === "" && parsed.password === "", "HTTP_TARGET_USERINFO", "user information is forbidden");
  assert(parsed.hash === "", "HTTP_TARGET_FRAGMENT", "fragments are forbidden");

  const authority = target.slice(target.indexOf("//") + 2).split(/[/?#]/u, 1)[0];
  assert(!/[^\x00-\x7f]/u.test(authority), "HTTP_TARGET_ASCII_HOST", "host source must be ASCII");
  assert(parsed.hostname === parsed.hostname.toLowerCase(), "HTTP_TARGET_CANONICAL", "host must be lowercase");
  assert(parsed.pathname.startsWith("/"), "HTTP_TARGET_CANONICAL", "path must be explicit");

  for (const match of target.matchAll(/%([0-9A-Fa-f]{2})/gu)) {
    const hex = match[1];
    const decoded = String.fromCharCode(Number.parseInt(hex, 16));
    assert(hex === hex.toUpperCase() && !/[A-Za-z0-9._~-]/u.test(decoded), "HTTP_TARGET_PERCENT_ENCODING", "percent encoding is not canonical");
  }
  assert(!/%(?![0-9A-Fa-f]{2})/u.test(target), "HTTP_TARGET_PERCENT_ENCODING", "invalid percent encoding");

  const queryStart = target.indexOf("?");
  if (queryStart >= 0) {
    const query = target.slice(queryStart + 1);
    assert(query.length > 0, "HTTP_TARGET_QUERY_ORDER", "empty query delimiter is forbidden");
    const pairs = query.split("&");
    const sorted = [...pairs].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    assert(pairs.every((pair, index) => pair === sorted[index]), "HTTP_TARGET_QUERY_ORDER", "query pairs must be sorted by encoded bytes");
  }

  assert(target === parsed.href, "HTTP_TARGET_CANONICAL", "target is not in canonical WHATWG serialization");
  return parsed;
}

function isStrongEtag(value) {
  return typeof value === "string" && /^"[!#-~]*"$/u.test(value);
}

function validatePostconditions(expected, observed, prefix) {
  const expectedByName = new Map(expected.map((entry) => [entry.name ?? entry.path, entry]));
  assert(expectedByName.size === expected.length, `${prefix}_POSTCONDITION_DUPLICATE`, "postconditions must be unique");
  for (const commitment of expected) {
    if (commitment.operator === "equals") {
      assert(typeof commitment.expected_sha256 === "string", `${prefix}_POSTCONDITION_COMMITMENT`, "equals requires a committed digest");
    } else {
      assert(commitment.expected_sha256 === null, `${prefix}_POSTCONDITION_COMMITMENT`, "a presence test requires a null digest");
    }
  }
  assert(observed.length === expected.length, `${prefix}_POSTCONDITION_MISMATCH`, "observation must include every committed postcondition");
  for (const actual of observed) {
    const key = actual.name ?? actual.path;
    const commitment = expectedByName.get(key);
    assert(commitment && actual.established === true, `${prefix}_POSTCONDITION_MISMATCH`, `postcondition ${key} was not established`);
    if (commitment.operator === "equals") {
      assert(actual.observed_sha256 === commitment.expected_sha256, `${prefix}_POSTCONDITION_MISMATCH`, `postcondition ${key} digest mismatch`);
    } else {
      assert(actual.observed_sha256 === null, `${prefix}_POSTCONDITION_MISMATCH`, `presence postcondition ${key} requires a null digest`);
    }
  }
}

function validateHttp(vector) {
  validateReceiptLifecycle(vector);
  const profile = "effect-transaction/http-conditional/0.1";
  const { context, documents: d } = vector;
  const args = d.arguments;
  const pre = d.pre_state;
  const claim = d.resource_claim;
  const expected = d.expected_effect;
  const dispatch = d.dispatch_evidence;
  const observation = d.observation_evidence;
  const reconciliation = d.reconciliation_evidence;

  envelope(args, profile, "arguments", ["method", "media_type", "headers", "body_sha256"], ["idempotency_key"]);
  envelope(pre, profile, "pre_state", ["target", "exists"], ["strong_etag"]);
  envelope(claim, profile, "resource_claim", ["origin", "target", "method"]);
  envelope(expected, profile, "expected_effect", ["allowed_status_classes", "postconditions"], ["response_body_sha256"]);
  envelope(dispatch, profile, "dispatch_evidence", ["attempt_id", "grant_id", "target", "method", "condition", "body_sha256", "journaled_at_ms", "first_request_byte_at_ms", "redirect_count"]);
  envelope(observation, profile, "observation_evidence", ["attempt_id", "target", "observed_at_ms", "transport_outcome", "postconditions"], ["status", "response_sha256", "application_transaction_id"]);
  if (reconciliation !== undefined) {
    envelope(reconciliation, profile, "reconciliation_evidence", ["attempt_id", "target", "observed_at_ms", "attribution", "postconditions"]);
  }

  const target = canonicalHttpTarget(context.target);
  assert(pre.target === context.target && claim.target === context.target && dispatch.target === context.target && observation.target === context.target, "HTTP_TARGET_MISMATCH", "all documents must bind the same target");
  if (reconciliation !== undefined) {
    assert(reconciliation.target === context.target, "HTTP_TARGET_MISMATCH", "reconciliation must bind the same target");
  }
  assert(claim.origin === target.origin, "HTTP_ORIGIN_MISMATCH", "claim origin must equal target origin");
  assert(["PUT", "PATCH", "DELETE"].includes(args.method), "HTTP_METHOD", "unsupported method");
  assert(claim.method === args.method && dispatch.method === args.method, "HTTP_METHOD_MISMATCH", "method commitments differ");

  assert(args.headers !== null && typeof args.headers === "object" && !Array.isArray(args.headers), "PROFILE_SCHEMA", "headers must be an object");
  for (const name of Object.keys(args.headers)) {
    assert(name === name.toLowerCase() && !forbiddenHttpHeaders.has(name) && !name.startsWith("proxy-"), "HTTP_HEADER_FORBIDDEN", `header ${name} is forbidden`);
  }
  if (Object.hasOwn(args, "idempotency_key")) assert(args.idempotency_key === context.grant_id, "HTTP_IDEMPOTENCY_MISMATCH", "idempotency key must equal grant id");

  if (pre.exists) {
    assert(isStrongEtag(pre.strong_etag), "HTTP_ETAG_WEAK", "existing resources require a strong ETag");
    assert(dispatch.condition.name === "if-match" && dispatch.condition.value === pre.strong_etag, "HTTP_CONDITION_MISMATCH", "executor condition must be the committed If-Match");
  } else {
    assert(!Object.hasOwn(pre, "strong_etag"), "HTTP_ETAG_CREATE", "create-only state cannot carry an ETag");
    assert(args.method === "PUT", "HTTP_CREATE_METHOD", "create-only effects require PUT");
    assert(dispatch.condition.name === "if-none-match" && dispatch.condition.value === "*", "HTTP_CONDITION_MISMATCH", "create-only effects require If-None-Match: *");
  }

  assert(dispatch.grant_id === context.grant_id, "HTTP_GRANT_MISMATCH", "dispatch grant mismatch");
  assert(dispatch.body_sha256 === args.body_sha256, "HTTP_BODY_MISMATCH", "dispatched body digest differs");
  assert(dispatch.redirect_count === 0, "HTTP_REDIRECT", "redirects are forbidden");
  assert(dispatch.journaled_at_ms < dispatch.first_request_byte_at_ms, "HTTP_DISPATCH_ORDER", "journal must precede the first request byte");
  assert(observation.attempt_id === dispatch.attempt_id, "HTTP_ATTEMPT_MISMATCH", "observation attempt mismatch");
  assert(observation.observed_at_ms > dispatch.first_request_byte_at_ms, "HTTP_OBSERVATION_ORDER", "observation must follow dispatch");

  if (observation.transport_outcome === "response") {
    assert(Number.isInteger(observation.status) && typeof observation.response_sha256 === "string", "PROFILE_SCHEMA", "response evidence is incomplete");
    assert(expected.allowed_status_classes.includes(Math.floor(observation.status / 100)), "HTTP_STATUS_UNCOMMITTED", "response status class was not committed");
    if (expected.response_body_sha256) assert(observation.response_sha256 === expected.response_body_sha256, "HTTP_RESPONSE_MISMATCH", "response digest mismatch");
    validatePostconditions(expected.postconditions, observation.postconditions, "HTTP");
  } else {
    assert(
      !Object.hasOwn(observation, "status")
        && !Object.hasOwn(observation, "response_sha256")
        && !Object.hasOwn(observation, "application_transaction_id")
        && observation.postconditions.length === 0,
      "HTTP_AMBIGUOUS_EVIDENCE",
      "ambiguous transport evidence must not include response-bound evidence",
    );
  }

  if (reconciliation !== undefined) {
    assert(reconciliation.attempt_id === dispatch.attempt_id && reconciliation.observed_at_ms >= observation.observed_at_ms, "HTTP_RECONCILIATION_ORDER", "reconciliation identity or time mismatch");
    assert(reconciliation.attribution.kind !== "none" && typeof reconciliation.attribution.value === "string", "HTTP_RECONCILIATION_UNATTRIBUTED", "reconciliation requires attribution bound to the target");
    validatePostconditions(expected.postconditions, reconciliation.postconditions, "HTTP");
  }
}

function validJsonPointer(path) {
  return typeof path === "string" && path.startsWith("/") && !/~(?![01])/u.test(path);
}

function jsonPointerTokens(path) {
  if (!validJsonPointer(path)) return null;
  return path.slice(1).split("/").map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"));
}

function overwritesProtectedMetadata(path) {
  const tokens = jsonPointerTokens(path);
  if (tokens === null) return false;
  return [
    ["metadata", "uid"],
    ["metadata", "resourceVersion"],
  ].some((protectedPath) =>
    tokens.length <= protectedPath.length
      && tokens.every((token, index) => token === protectedPath[index]));
}

function parseKubernetesTarget(target) {
  assert(typeof target === "string" && target.length <= 4096, "K8S_TARGET_SYNTAX", "target must be text of 4,096 characters or less");
  assert(!/[\u0000-\u0020\u007f%]/u.test(target), "K8S_TARGET_SYNTAX", "target contains a forbidden character");
  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    fail("K8S_TARGET_SYNTAX", "target is not an absolute URI");
  }
  assert(parsed.protocol === "k8s:", "K8S_TARGET_SCHEME", "target must use k8s");
  assert(parsed.username === "" && parsed.password === "" && parsed.hash === "", "K8S_TARGET_SYNTAX", "userinfo and fragments are forbidden");
  assert(/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/u.test(parsed.hostname), "K8S_TARGET_TRUST_DOMAIN", "cluster trust domain is not canonical");
  assert([...parsed.searchParams.keys()].length === 1 && parsed.searchParams.has("uid"), "K8S_TARGET_QUERY", "target query must contain only uid");
  const uid = parsed.searchParams.get("uid");
  assert(/^[A-Za-z0-9-]{8,128}$/u.test(uid), "K8S_TARGET_UID", "uid is not canonical");
  assert(target === `k8s://${parsed.hostname}${parsed.pathname}?uid=${uid}`, "K8S_TARGET_CANONICAL", "target is not in canonical profile serialization");

  const segments = parsed.pathname.split("/").slice(1);
  assert(segments.every((segment) => /^[A-Za-z0-9._-]+$/u.test(segment)), "K8S_TARGET_API_PATH", "API path segment is not canonical");
  assert(!segments.some((segment) => ["exec", "attach", "proxy", "portforward"].includes(segment)), "K8S_TARGET_FORBIDDEN_ENDPOINT", "forbidden Kubernetes endpoint");
  let resource;
  if (segments[0] === "api" && segments.length >= 2) resource = segments.slice(2);
  else if (segments[0] === "apis" && segments.length >= 3) resource = segments.slice(3);
  else fail("K8S_TARGET_API_PATH", "target is outside canonical Kubernetes APIs");

  if (resource[0] === "namespaces") {
    assert(resource.length === 4 || resource.length === 5, "K8S_TARGET_COLLECTION", "namespaced target must name one object");
  } else {
    assert(resource.length === 2 || resource.length === 3, "K8S_TARGET_COLLECTION", "cluster target must name one object");
  }
  return { cluster: parsed.hostname, apiPath: parsed.pathname, uid };
}

function validateKubernetes(vector) {
  validateReceiptLifecycle(vector);
  const profile = "effect-transaction/kubernetes-json-patch/0.1";
  const { context, documents: d } = vector;
  const args = d.arguments;
  const pre = d.pre_state;
  const claim = d.resource_claim;
  const expected = d.expected_effect;
  const dispatch = d.dispatch_evidence;
  const observation = d.observation_evidence;
  const reconciliation = d.reconciliation_evidence;

  envelope(args, profile, "arguments", ["media_type", "patch_utf8_base64url", "patch_sha256", "operations"]);
  envelope(pre, profile, "pre_state", ["cluster_trust_domain", "api_path", "uid", "resource_version", "object_sha256"]);
  envelope(claim, profile, "resource_claim", ["cluster_trust_domain", "api_path", "uid", "write_set"]);
  envelope(expected, profile, "expected_effect", ["postconditions"]);
  envelope(dispatch, profile, "dispatch_evidence", ["attempt_id", "grant_id", "target", "api_server_identity", "patch_sha256", "journaled_at_ms", "first_patch_byte_at_ms"]);
  envelope(observation, profile, "observation_evidence", ["attempt_id", "target", "observed_at_ms", "transport_outcome", "postconditions"], ["http_status", "uid", "resource_version", "object_sha256", "attribution"]);
  if (reconciliation !== undefined) {
    envelope(reconciliation, profile, "reconciliation_evidence", ["attempt_id", "target", "observed_at_ms", "uid", "resource_version", "object_sha256", "attribution", "postconditions"]);
  }

  const target = parseKubernetesTarget(context.target);
  assert(pre.cluster_trust_domain === target.cluster && claim.cluster_trust_domain === target.cluster, "K8S_CLUSTER_MISMATCH", "cluster trust domains differ");
  assert(pre.api_path === target.apiPath && claim.api_path === target.apiPath, "K8S_API_PATH_MISMATCH", "API paths differ");
  assert(pre.uid === target.uid && claim.uid === target.uid, "K8S_TARGET_UID_MISMATCH", "target UID differs from committed UID");
  assert(dispatch.target === context.target && observation.target === context.target, "K8S_TARGET_MISMATCH", "evidence target mismatch");
  if (reconciliation !== undefined) {
    assert(reconciliation.target === context.target, "K8S_TARGET_MISMATCH", "reconciliation target mismatch");
  }
  assert(dispatch.grant_id === context.grant_id, "K8S_GRANT_MISMATCH", "dispatch grant mismatch");

  const patchBytes = Buffer.from(args.patch_utf8_base64url, "base64url");
  assert(patchBytes.toString("base64url") === args.patch_utf8_base64url, "K8S_PATCH_ENCODING", "patch must use unpadded canonical base64url");
  assert(sha256(patchBytes) === args.patch_sha256, "K8S_PATCH_DIGEST", "patch digest mismatch");
  let decoded;
  try {
    decoded = parseJsonWithoutDuplicateKeys(new TextDecoder("utf-8", { fatal: true }).decode(patchBytes));
  } catch (error) {
    if (error instanceof ProfileError) throw error;
    fail("K8S_PATCH_JSON", "patch bytes are not strict UTF-8 JSON");
  }
  assert(JSON.stringify(decoded) === JSON.stringify(args.operations), "K8S_PATCH_BYTES_MISMATCH", "parsed patch bytes differ from committed operations");
  assert(Array.isArray(decoded) && decoded.length >= 3 && decoded.length <= 256, "K8S_PATCH_SHAPE", "patch operation count is out of bounds");

  const uidTest = decoded[0];
  const rvTest = decoded[1];
  assert(uidTest?.op === "test" && uidTest.path === "/metadata/uid" && uidTest.value === pre.uid, "K8S_PATCH_UID_TEST", "first operation must test the committed UID");
  assert(rvTest?.op === "test" && rvTest.path === "/metadata/resourceVersion" && rvTest.value === pre.resource_version, "K8S_PATCH_RV_TEST", "second operation must test the committed resourceVersion");

  const writeSet = claim.write_set;
  assert(Array.isArray(writeSet) && writeSet.length > 0 && writeSet.every(validJsonPointer), "K8S_JSON_POINTER", "write set contains an invalid JSON Pointer");
  const sortedWriteSet = [...new Set(writeSet)].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  assert(writeSet.length === sortedWriteSet.length && writeSet.every((path, index) => path === sortedWriteSet[index]), "K8S_WRITE_SET_CANONICAL", "write set must be sorted and unique");

  const mutationPaths = [];
  for (const operation of decoded.slice(2)) {
    assert(operation !== null && typeof operation === "object" && ["add", "remove", "replace", "test"].includes(operation.op), "K8S_PATCH_OPERATION", "patch operation is not permitted");
    exactKeys(operation, ["op", "path"], operation.op === "remove" ? [] : ["value"], "PROFILE_SCHEMA");
    if (["add", "replace", "test"].includes(operation.op)) assert(Object.hasOwn(operation, "value"), "PROFILE_SCHEMA", `${operation.op} requires value`);
    assert(validJsonPointer(operation.path), "K8S_JSON_POINTER", "patch path is not a valid JSON Pointer");
    if (operation.op !== "test") {
      assert(!overwritesProtectedMetadata(operation.path), "K8S_PATCH_IMMUTABLE_METADATA", "identity and concurrency metadata cannot be overwritten directly or through an ancestor");
      assert(writeSet.includes(operation.path), "K8S_PATCH_WRITE_SET", `write path ${operation.path} is not in the resource claim`);
      mutationPaths.push(operation.path);
    }
  }
  const actualWriteSet = [...new Set(mutationPaths)].sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  assert(actualWriteSet.length === writeSet.length && actualWriteSet.every((path, index) => path === writeSet[index]), "K8S_PATCH_WRITE_SET_MISMATCH", "claim write set must equal the patch mutation set");

  assert(dispatch.patch_sha256 === args.patch_sha256, "K8S_DISPATCH_PATCH_MISMATCH", "dispatched patch digest differs");
  assert(dispatch.journaled_at_ms < dispatch.first_patch_byte_at_ms, "K8S_DISPATCH_ORDER", "journal must precede the first PATCH byte");
  assert(observation.attempt_id === dispatch.attempt_id, "K8S_ATTEMPT_MISMATCH", "observation attempt mismatch");
  assert(observation.observed_at_ms > dispatch.first_patch_byte_at_ms, "K8S_OBSERVATION_ORDER", "observation must follow dispatch");
  if (observation.transport_outcome === "response") {
    assert(
      Number.isInteger(observation.http_status)
        && observation.http_status >= 200
        && observation.http_status <= 299,
      "K8S_RESPONSE_STATUS",
      "a succeeded Kubernetes response requires HTTP status 200 through 299",
    );
    assert(observation.uid === pre.uid, "K8S_OBSERVED_UID_MISMATCH", "response UID differs");
    assert(typeof observation.resource_version === "string" && observation.resource_version.length > 0, "K8S_OBSERVED_RV", "response resourceVersion is missing");
    validatePostconditions(expected.postconditions, observation.postconditions, "K8S");
  } else {
    assert(
      !Object.hasOwn(observation, "http_status")
        && !Object.hasOwn(observation, "uid")
        && !Object.hasOwn(observation, "resource_version")
        && !Object.hasOwn(observation, "object_sha256")
        && !Object.hasOwn(observation, "attribution")
        && observation.postconditions.length === 0,
      "K8S_AMBIGUOUS_EVIDENCE",
      "ambiguous transport evidence must not include response-bound evidence",
    );
  }

  if (reconciliation !== undefined) {
    assert(reconciliation.attempt_id === dispatch.attempt_id && reconciliation.observed_at_ms >= observation.observed_at_ms, "K8S_RECONCILIATION_ORDER", "reconciliation identity or time mismatch");
    assert(reconciliation.uid === pre.uid, "K8S_RECONCILIATION_UID", "reconciliation UID differs");
    assert(reconciliation.attribution.kind !== "none" && typeof reconciliation.attribution.value === "string", "K8S_RECONCILIATION_UNATTRIBUTED", "reconciliation requires audit or marker attribution");
    validatePostconditions(expected.postconditions, reconciliation.postconditions, "K8S");
  }
}

function runSuite(vectorFile, validator, schemaValidators) {
  const suite = readJson(join(vectorsDirectory, vectorFile));
  const bases = new Map(suite.positive.map((vector) => [vector.name, vector]));
  let passed = 0;
  for (const vector of suite.positive) {
    validateDocumentsAgainstSchemas(vector, schemaValidators);
    validator(vector);
    passed += 1;
  }
  for (const vector of suite.adversarial) {
    const base = bases.get(vector.base);
    assert(base, "VECTOR_BASE", `missing vector base ${vector.base}`);
    const candidate = applyMutations(base, vector.mutations, suite.profile);
    let schemaFailure = null;
    try {
      validateDocumentsAgainstSchemas(candidate, schemaValidators);
    } catch (error) {
      if (!(error instanceof ProfileError)) throw error;
      schemaFailure = error;
    }
    try {
      validator(candidate);
      if (schemaFailure !== null) throw schemaFailure;
      fail("VECTOR_FALSE_ACCEPT", `${vector.name} was accepted`);
    } catch (error) {
      if (!(error instanceof ProfileError)) throw error;
      assert(error.code === vector.expect_code, "VECTOR_WRONG_REJECTION", `${vector.name}: expected ${vector.expect_code}, got ${error.code}: ${error.message}`);
    }
    passed += 1;
  }
  return { passed, positive: suite.positive.length, adversarial: suite.adversarial.length };
}

const httpSchemas = validateProfileRegistry("http-conditional-0.1.profile.json");
const kubernetesSchemas = validateProfileRegistry("kubernetes-json-patch-0.1.profile.json");
const http = runSuite("http-conditional-0.1.json", validateHttp, httpSchemas);
const kubernetes = runSuite("kubernetes-json-patch-0.1.json", validateKubernetes, kubernetesSchemas);
console.log(`Profile validation passed: ${http.passed + kubernetes.passed} vectors (${http.positive + kubernetes.positive} positive, ${http.adversarial + kubernetes.adversarial} adversarial).`);

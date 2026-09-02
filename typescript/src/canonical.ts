import { createHash } from "node:crypto";

export class CanonicalizationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "CanonicalizationError";
    this.code = code;
  }
}

export const MAX_TRANSPORT_INPUT_BYTES = 1024 * 1024;
export const MAX_TRANSPORT_NESTING_DEPTH = 64;
export const MAX_TRANSPORT_NODES = 100_000;

function fail(code: string, message: string): never {
  throw new CanonicalizationError(code, message);
}

function assertScalarString(value: string, context: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail("invalid_unicode", `${context} contains an unpaired high surrogate`);
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      fail("invalid_unicode", `${context} contains an unpaired low surrogate`);
    }
  }
}

export function compareUnicodeScalars(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) as number);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) as number);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) {
      return leftPoints[index] < rightPoints[index] ? -1 : 1;
    }
  }
  return leftPoints.length - rightPoints.length;
}

function quoteString(value: string): string {
  assertScalarString(value, "string");
  let output = '"';
  for (const scalar of value) {
    const codePoint = scalar.codePointAt(0) as number;
    if (scalar === '"') {
      output += '\\"';
    } else if (scalar === "\\") {
      output += "\\\\";
    } else if (scalar === "\b") {
      output += "\\b";
    } else if (scalar === "\t") {
      output += "\\t";
    } else if (scalar === "\n") {
      output += "\\n";
    } else if (scalar === "\f") {
      output += "\\f";
    } else if (scalar === "\r") {
      output += "\\r";
    } else if (codePoint <= 0x1f) {
      output += `\\u${codePoint.toString(16).padStart(4, "0")}`;
    } else {
      output += scalar;
    }
  }
  return `${output}"`;
}

function canonicalizeInner(value: unknown, ancestors: Set<object>): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "string") {
    return quoteString(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      fail("invalid_number", "numbers must be finite safe integers");
    }
    if (Object.is(value, -0)) {
      fail("invalid_number", "negative zero is not canonical");
    }
    return String(value);
  }
  if (typeof value !== "object") {
    fail("unsupported_type", `unsupported JSON value type: ${typeof value}`);
  }

  if (ancestors.has(value)) {
    fail("cyclic_value", "cyclic values cannot be canonicalized");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const elements: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          fail("sparse_array", "sparse arrays are not canonical JSON");
        }
        elements.push(canonicalizeInner(value[index], ancestors));
      }
      const extraKeys = Reflect.ownKeys(value).filter((key) => {
        if (key === "length") return false;
        return typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key);
      });
      if (extraKeys.length > 0) {
        fail("array_property", "arrays cannot carry named or symbolic properties");
      }
      return `[${elements.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail("non_plain_object", "only plain objects are canonical JSON objects");
    }

    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== "string")) {
      fail("symbol_key", "JSON object keys must be strings");
    }
    const keys = (ownKeys as string[]).sort(compareUnicodeScalars);
    const entries: string[] = [];
    for (const key of keys) {
      assertScalarString(key, "object key");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        fail("object_property", "object properties must be enumerable data properties");
      }
      entries.push(`${quoteString(key)}:${canonicalizeInner(descriptor.value, ancestors)}`);
    }
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function enforceValueBudget(root: unknown): void {
  const pending: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 1 }];
  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop() as { value: unknown; depth: number };
    nodes += 1;
    if (nodes > MAX_TRANSPORT_NODES) {
      fail("resource_limit", `JSON value exceeds ${MAX_TRANSPORT_NODES} nodes`);
    }
    if (current.depth > MAX_TRANSPORT_NESTING_DEPTH) {
      fail(
        "resource_limit",
        `JSON value exceeds nesting depth ${MAX_TRANSPORT_NESTING_DEPTH}`,
      );
    }
    if (current.value === null || typeof current.value !== "object") continue;
    for (const key of Reflect.ownKeys(current.value)) {
      if (key === "length" && Array.isArray(current.value)) continue;
      const descriptor = Object.getOwnPropertyDescriptor(current.value, key);
      if (descriptor !== undefined && "value" in descriptor) {
        pending.push({ value: descriptor.value, depth: current.depth + 1 });
      }
    }
  }
}

/** Return the canonical encoding of the ETP JSON subset. */
export function canonicalJson(value: unknown): string {
  enforceValueBudget(value);
  return canonicalizeInner(value, new Set<object>());
}

class StrictJsonParser {
  private index = 0;
  private nodes = 0;
  private readonly source: string;

  constructor(source: string) {
    this.source = source;
  }

  parse(): unknown {
    this.skipWhitespace();
    const value = this.value(1);
    this.skipWhitespace();
    if (this.index !== this.source.length) {
      this.invalid("unexpected trailing input");
    }
    canonicalJson(value);
    return value;
  }

  private value(depth: number): unknown {
    if (depth > MAX_TRANSPORT_NESTING_DEPTH) {
      fail(
        "transport_limit",
        `JSON value exceeds nesting depth ${MAX_TRANSPORT_NESTING_DEPTH}`,
      );
    }
    this.nodes += 1;
    if (this.nodes > MAX_TRANSPORT_NODES) {
      fail("transport_limit", `JSON value exceeds ${MAX_TRANSPORT_NODES} nodes`);
    }
    const current = this.source[this.index];
    if (current === "{") {
      return this.object(depth);
    }
    if (current === "[") {
      return this.array(depth);
    }
    if (current === '"') return this.string();
    if (current === "t") return this.keyword("true", true);
    if (current === "f") return this.keyword("false", false);
    if (current === "n") return this.keyword("null", null);
    if (current === "-" || (current >= "0" && current <= "9")) return this.number();
    this.invalid("expected a JSON value");
  }

  private object(depth: number): Record<string, unknown> {
    this.index += 1;
    this.skipWhitespace();
    const result: Record<string, unknown> = {};
    const keys = new Set<string>();
    if (this.take("}")) return result;
    while (true) {
      if (this.source[this.index] !== '"') this.invalid("expected an object key");
      const key = this.string();
      if (keys.has(key)) {
        fail("duplicate_key", `duplicate JSON object key at offset ${this.index}: ${key}`);
      }
      keys.add(key);
      this.skipWhitespace();
      if (!this.take(":")) this.invalid("expected ':' after object key");
      this.skipWhitespace();
      const value = this.value(depth + 1);
      Object.defineProperty(result, key, {
        value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      this.skipWhitespace();
      if (this.take("}")) return result;
      if (!this.take(",")) this.invalid("expected ',' or '}' in object");
      this.skipWhitespace();
    }
  }

  private array(depth: number): unknown[] {
    this.index += 1;
    this.skipWhitespace();
    const result: unknown[] = [];
    if (this.take("]")) return result;
    while (true) {
      result.push(this.value(depth + 1));
      this.skipWhitespace();
      if (this.take("]")) return result;
      if (!this.take(",")) this.invalid("expected ',' or ']' in array");
      this.skipWhitespace();
    }
  }

  private string(): string {
    this.index += 1;
    let result = "";
    while (this.index < this.source.length) {
      const current = this.source[this.index];
      if (current === '"') {
        this.index += 1;
        return result;
      }
      if (current === "\\") {
        this.index += 1;
        const escape = this.source[this.index];
        const simple: Record<string, string> = {
          '"': '"',
          "\\": "\\",
          "/": "/",
          b: "\b",
          f: "\f",
          n: "\n",
          r: "\r",
          t: "\t",
        };
        if (Object.hasOwn(simple, escape)) {
          result += simple[escape];
          this.index += 1;
          continue;
        }
        if (escape !== "u") this.invalid("invalid string escape");
        this.index += 1;
        const first = this.hexUnit();
        if (first >= 0xd800 && first <= 0xdbff) {
          if (this.source.slice(this.index, this.index + 2) !== "\\u") {
            this.invalid("high surrogate must be followed by a low surrogate escape");
          }
          this.index += 2;
          const second = this.hexUnit();
          if (!(second >= 0xdc00 && second <= 0xdfff)) {
            this.invalid("high surrogate must be followed by a low surrogate escape");
          }
          result += String.fromCodePoint(
            0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00),
          );
        } else if (first >= 0xdc00 && first <= 0xdfff) {
          this.invalid("unpaired low surrogate escape");
        } else {
          result += String.fromCharCode(first);
        }
        continue;
      }

      const unit = this.source.charCodeAt(this.index);
      if (unit <= 0x1f) this.invalid("unescaped control character in string");
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = this.source.charCodeAt(this.index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) this.invalid("unpaired high surrogate");
        result += this.source.slice(this.index, this.index + 2);
        this.index += 2;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        this.invalid("unpaired low surrogate");
      } else {
        result += current;
        this.index += 1;
      }
    }
    this.invalid("unterminated string");
  }

  private hexUnit(): number {
    const token = this.source.slice(this.index, this.index + 4);
    if (!/^[0-9a-fA-F]{4}$/u.test(token)) this.invalid("invalid Unicode escape");
    this.index += 4;
    return Number.parseInt(token, 16);
  }

  private number(): number {
    const start = this.index;
    if (this.take("-")) {
      if (this.index >= this.source.length) this.invalid("incomplete number");
    }
    if (this.take("0")) {
      if (/[0-9]/u.test(this.source[this.index] ?? "")) {
        this.invalid("leading zero in number");
      }
    } else {
      const first = this.source[this.index];
      if (!(first >= "1" && first <= "9")) this.invalid("invalid integer");
      this.index += 1;
      while (/[0-9]/u.test(this.source[this.index] ?? "")) this.index += 1;
    }
    if ([".", "e", "E"].includes(this.source[this.index] ?? "")) {
      fail(
        "invalid_number_syntax",
        `non-integer JSON number form at offset ${start}`,
      );
    }
    const token = this.source.slice(start, this.index);
    const result = Number(token);
    if (!Number.isSafeInteger(result) || Object.is(result, -0)) {
      fail("invalid_number", `number is not a canonical safe integer: ${token}`);
    }
    return result;
  }

  private keyword<T>(token: string, value: T): T {
    if (this.source.slice(this.index, this.index + token.length) !== token) {
      this.invalid(`expected '${token}'`);
    }
    this.index += token.length;
    return value;
  }

  private skipWhitespace(): void {
    while ([" ", "\t", "\r", "\n"].includes(this.source[this.index] ?? "")) {
      this.index += 1;
    }
  }

  private take(expected: string): boolean {
    if (this.source[this.index] !== expected) return false;
    this.index += 1;
    return true;
  }

  private invalid(message: string): never {
    fail("invalid_json", `${message} at offset ${this.index}`);
  }
}

/** Parse the ETP JSON subset and reject duplicate keys or invalid numbers. */
export function parseStrictJson(text: string): unknown {
  if (Buffer.byteLength(text, "utf8") > MAX_TRANSPORT_INPUT_BYTES) {
    fail(
      "transport_limit",
      `JSON input exceeds ${MAX_TRANSPORT_INPUT_BYTES} UTF-8 bytes`,
    );
  }
  return new StrictJsonParser(text).parse();
}

export function commitment(domain: string, value: unknown): string {
  if (domain.length === 0 || domain.includes("\u0000")) {
    fail("invalid_domain", "hash domain must not be empty or contain a NUL byte");
  }
  assertScalarString(domain, "hash domain");
  const hash = createHash("sha256");
  hash.update(Buffer.from(domain, "utf8"));
  hash.update(Buffer.from([0]));
  hash.update(Buffer.from(canonicalJson(value), "utf8"));
  return `sha256:${hash.digest("hex")}`;
}

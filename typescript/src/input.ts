import { VerificationError } from "./verify.ts";

export const CORE_PROFILE = "effect-transaction/core/0.1";

export interface VerificationInput {
  transaction: unknown;
  expected: unknown | null;
}

function object(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new VerificationError("record_type", path, "expected a JSON object");
  }
  return value as Record<string, unknown>;
}

/** Unwrap a lifecycle bundle or a test-vector envelope. */
export function unwrapVerificationInput(value: unknown): VerificationInput {
  const input = object(value, "input");
  if (!Object.hasOwn(input, "transaction")) {
    return { transaction: input, expected: null };
  }

  const allowed = new Set(["profile", "description", "transaction", "expected"]);
  for (const required of ["profile", "transaction", "expected"]) {
    if (!Object.hasOwn(input, required)) {
      throw new VerificationError(
        "missing_field",
        `vector.${required}`,
        "required test-vector field is missing",
      );
    }
  }
  for (const field of Object.keys(input)) {
    if (!allowed.has(field)) {
      throw new VerificationError(
        "unknown_field",
        `vector.${field}`,
        "test-vector field is not permitted",
      );
    }
  }
  if (input.profile !== CORE_PROFILE) {
    throw new VerificationError(
      "unsupported_profile",
      "vector.profile",
      `expected ${CORE_PROFILE}`,
    );
  }
  if (Object.hasOwn(input, "description")) {
    if (typeof input.description !== "string") {
      throw new VerificationError("string", "vector.description", "expected a string");
    }
    if (
      [...input.description].length > 4096 ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(input.description)
    ) {
      throw new VerificationError(
        "invalid_description",
        "vector.description",
        "description exceeds 4,096 characters or contains a control character",
      );
    }
  }
  object(input.expected, "vector.expected");
  return { transaction: input.transaction, expected: input.expected };
}

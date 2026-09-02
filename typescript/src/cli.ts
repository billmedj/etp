import { readFile } from "node:fs/promises";
import { canonicalJson, parseStrictJson } from "./canonical.ts";
import { unwrapVerificationInput } from "./input.ts";
import { VerificationError, verifyTransaction } from "./verify.ts";

async function main(): Promise<void> {
  const path = process.argv[2];
  if (path === undefined || process.argv.length !== 3) {
    console.error("Usage: npm run verify -- <transaction.json>");
    process.exitCode = 64;
    return;
  }
  try {
    const bytes = await readFile(path);
    const input = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed = parseStrictJson(input);
    const { transaction, expected } = unwrapVerificationInput(parsed);
    const verified = verifyTransaction(transaction);
    if (expected !== null && canonicalJson(expected) !== canonicalJson(verified)) {
      throw new VerificationError(
        "expected_mismatch",
        "vector.expected",
        "computed result does not match the expected result",
      );
    }
    console.log(JSON.stringify({ valid: true, ...verified }, null, 2));
  } catch (error) {
    if (error instanceof VerificationError) {
      console.error(JSON.stringify({
        valid: false,
        code: error.code,
        path: error.path,
        message: error.message,
      }, null, 2));
    } else if (error instanceof Error) {
      console.error(JSON.stringify({
        valid: false,
        code: "invalid_input",
        message: error.message,
      }, null, 2));
    }
    process.exitCode = 1;
  }
}

await main();

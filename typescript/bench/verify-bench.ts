import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { parseStrictJson } from "../src/canonical.ts";
import { verifyTransaction } from "../src/verify.ts";

const raw = await readFile(
  new URL("../../vectors/positive-chain.json", import.meta.url),
  "utf8",
);
const parsed = parseStrictJson(raw) as Record<string, unknown>;
const transaction = parsed.transaction;
const requested = Number.parseInt(process.env.ETP_BENCH_ITERATIONS ?? "2000", 10);
if (!Number.isSafeInteger(requested) || requested < 1 || requested > 1_000_000) {
  throw new Error("ETP_BENCH_ITERATIONS must be an integer from 1 to 1,000,000");
}

for (let index = 0; index < Math.min(requested, 100); index += 1) {
  verifyTransaction(transaction);
}

function measure(operation: () => void): { total_ms: number; mean_us: number; ops_per_second: number } {
  const started = performance.now();
  for (let index = 0; index < requested; index += 1) operation();
  const total = performance.now() - started;
  return {
    total_ms: Number(total.toFixed(3)),
    mean_us: Number(((total * 1000) / requested).toFixed(3)),
    ops_per_second: Number(((requested * 1000) / total).toFixed(1)),
  };
}

const report = {
  benchmark: "effect-transaction/typescript/core-0.1",
  iterations: requested,
  environment: {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
  },
  operations: {
    verify_preparsed_complete_chain: measure(() => {
      verifyTransaction(transaction);
    }),
    strict_parse_and_verify_complete_chain: measure(() => {
      const value = parseStrictJson(raw) as Record<string, unknown>;
      verifyTransaction(value.transaction);
    }),
  },
  notes: [
    "No performance threshold is asserted.",
    "Use a pinned host and multiple process samples for comparative claims.",
  ],
};

process.stdout.write(JSON.stringify(report, null, 2) + "\n");

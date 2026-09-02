import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseStrictJson } from "../src/canonical.ts";
import { runConformanceSuite } from "../../conformance/runner.ts";

const runner = fileURLToPath(new URL("../../conformance/runner.ts", import.meta.url));

test("conformance manifest passes every category", async () => {
  const report = await runConformanceSuite();
  assert.equal(report.success, true);
  assert.equal(report.summary.failed, 0);
  assert.ok(report.summary.total >= 70);
  for (const category of [
    "binding", "issuance", "claim", "currentness", "time", "receipt",
    "reconciliation", "transport", "canonicalization",
  ]) {
    assert.ok(report.summary.categories[category]?.passed > 0, category);
  }
  assert.match(report.manifest_sha256, /^[0-9a-f]{64}$/u);
});

test("CLI writes a strict JSON report", async () => {
  const directory = await mkdtemp(join(tmpdir(), "etp-conformance-"));
  try {
    const reportPath = join(directory, "report.json");
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", runner, "--report", reportPath],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    const parsed = parseStrictJson(await readFile(reportPath, "utf8")) as Record<string, unknown>;
    assert.equal(parsed.success, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("CLI exits nonzero on a declared behavioral divergence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "etp-conformance-"));
  try {
    const manifestPath = join(directory, "divergent-manifest.json");
    const manifest = parseStrictJson(
      await readFile(new URL("../../conformance/manifest.json", import.meta.url), "utf8"),
    ) as Record<string, any>;
    manifest.cases.find((entry: Record<string, any>) =>
      entry.id === "chain.positive.complete").expected.state = "failed";
    await writeFile(manifestPath, JSON.stringify(manifest), "utf8");
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", runner, "--manifest", manifestPath],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 1, result.stderr);
    const report = parseStrictJson(result.stdout) as Record<string, any>;
    assert.equal(report.success, false);
    assert.equal(report.summary.failed, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("operation traces define non-mutation behavior", async () => {
  const directory = await mkdtemp(join(tmpdir(), "etp-conformance-"));
  try {
    const tracePath = join(directory, "operation-traces.json");
    const traces = parseStrictJson(
      await readFile(new URL("../../vectors/conformance-traces.json", import.meta.url), "utf8"),
    ) as Record<string, any>;
    const trace = traces.traces.find((entry: Record<string, any>) =>
      entry.id === "chain.positive.complete");
    trace.steps = [{ operation: "verify_fixture", fixture: "positive_not_dispatched" }];
    await writeFile(tracePath, JSON.stringify(traces), "utf8");

    const report = await runConformanceSuite(undefined, pathToFileURL(tracePath));
    const result = report.cases.find((entry) => entry.id === "chain.positive.complete");
    assert.equal(result?.pass, false);
    assert.equal(result?.actual.state, "not_dispatched");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("repeated claims use the sequential lifecycle oracle", async () => {
  const directory = await mkdtemp(join(tmpdir(), "etp-conformance-"));
  try {
    const tracePath = join(directory, "unlabelled-traces.json");
    const traces = parseStrictJson(
      await readFile(new URL("../../vectors/conformance-traces.json", import.meta.url), "utf8"),
    ) as Record<string, any>;
    const trace = traces.traces.find((entry: Record<string, any>) => entry.id === "claim.competing");
    delete trace.oracle;
    await writeFile(tracePath, JSON.stringify(traces), "utf8");

    await assert.rejects(
      runConformanceSuite(undefined, pathToFileURL(tracePath)),
      (error: any) => error?.code === "invalid_trace" && /sequential oracle/u.test(error.message),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("trace validation rejects unknown operations", async () => {
  const directory = await mkdtemp(join(tmpdir(), "etp-conformance-"));
  try {
    const tracePath = join(directory, "unknown-operation.json");
    const traces = parseStrictJson(
      await readFile(new URL("../../vectors/conformance-traces.json", import.meta.url), "utf8"),
    ) as Record<string, any>;
    traces.traces[0].steps = [{ operation: "accept_case_by_name" }];
    await writeFile(tracePath, JSON.stringify(traces), "utf8");

    await assert.rejects(
      runConformanceSuite(undefined, pathToFileURL(tracePath)),
      (error: any) => error?.code === "invalid_trace" && /operation is unknown/u.test(error.message),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

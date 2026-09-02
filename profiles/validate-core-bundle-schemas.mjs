import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const schemaDirectory = fileURLToPath(new URL("../schemas/", import.meta.url));
const vectorDirectory = fileURLToPath(new URL("../vectors/", import.meta.url));
const schemas = fs.readdirSync(schemaDirectory)
  .filter((name) => name.endsWith(".schema.json"))
  .map((name) => JSON.parse(fs.readFileSync(path.join(schemaDirectory, name), "utf8")));

const ajv = new Ajv2020({ strict: true, allErrors: true });
for (const schema of schemas) ajv.addSchema(schema);

const envelope = ajv.getSchema("https://billmedj.github.io/etp/schemas/test-vector-envelope-0.1.schema.json");
const lifecycle = ajv.getSchema("https://billmedj.github.io/etp/schemas/transaction-bundle-0.1.schema.json");
if (envelope === undefined || lifecycle === undefined) {
  throw new Error("core bundle schemas were not registered by their HTTPS identifiers");
}

for (const name of ["positive-chain.json", "positive-not-dispatched.json"]) {
  const vector = JSON.parse(fs.readFileSync(path.join(vectorDirectory, name), "utf8"));
  if (!envelope(vector)) {
    throw new Error(`${name} failed its test-vector envelope schema: ${ajv.errorsText(envelope.errors)}`);
  }
}

const positive = JSON.parse(
  fs.readFileSync(path.join(vectorDirectory, "positive-chain.json"), "utf8"),
);
const missingExpected = structuredClone(positive);
delete missingExpected.expected;
if (envelope(missingExpected)) throw new Error("vector envelope accepted a missing expected result");

const receiptWithoutGrant = structuredClone(positive.transaction);
delete receiptWithoutGrant.grant;
if (lifecycle(receiptWithoutGrant)) throw new Error("lifecycle accepted a receipt without a grant");

const reconciliationWithoutReceipt = structuredClone(positive.transaction);
delete reconciliationWithoutReceipt.receipt;
if (lifecycle(reconciliationWithoutReceipt)) {
  throw new Error("lifecycle accepted reconciliation records without a receipt");
}

const decided = structuredClone(positive.transaction);
delete decided.grant;
delete decided.receipt;
decided.reconciliations = [];
if (!lifecycle(decided)) {
  throw new Error(`valid decided lifecycle prefix was rejected: ${ajv.errorsText(lifecycle.errors)}`);
}

console.log(`Core schema validation passed: ${schemas.length} schemas and 2 envelopes.`);

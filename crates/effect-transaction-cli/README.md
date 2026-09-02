# ETP command-line interface

`etp` verifies ETP Core 0.1 transactions and computes record commitments. It
does not require a network connection.

```text
etp verify <PATH>
etp hash <KIND> <PATH>
```

Run through Cargo from the repository root:

```powershell
cargo run --locked -p effect-transaction-cli -- verify vectors/positive-chain.json
cargo run --locked -p effect-transaction-cli -- hash task-commitment <record.json>
```

Replace `<record.json>` with a file that contains one valid Core record of the
kind passed to `hash`.

`verify` accepts a transaction bundle or a published test-vector envelope. A
test-vector envelope must contain `profile`, `transaction`, and `expected`.
The command rejects unknown fields, duplicate fields, unsupported profiles,
oversized input, malformed records, invalid links, and expectation mismatches.

`hash` parses one record with the selected record kind. It validates the record
before it computes the domain-separated commitment.

Envelope metadata is not part of a commitment and does not grant authority.
This CLI does not sign records, authorize requests, claim grants, dispatch
effects, or observe target state.

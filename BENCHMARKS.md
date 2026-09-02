# Benchmark method

The TypeScript verifier includes a microbenchmark with no external runtime
dependencies. It measures these operations separately:

- verification of a parsed transaction chain;
- strict transport parsing and chain verification.

Run the benchmark from `typescript`:

```console
npm run benchmark
```

Set `ETP_BENCH_ITERATIONS` to select the sample size. The command writes JSON.
The output includes the Node.js version, platform, architecture, iteration
count, total duration, mean latency, and throughput.

Do not treat one result as a universal performance value. Results depend on
the runtime, processor settings, thermal state, process isolation, payload,
and reconciliation-chain length. A comparative test SHOULD fix these factors.
It SHOULD use independent processes, retain raw samples, and report a
distribution.

This benchmark does not measure signing, SQLite durability, policy evaluation,
target observation, network delay, or effect dispatch. Measure these operations
in an end-to-end benchmark for the applicable effect profile.

#!/usr/bin/env python3
"""Run the pinned bounded TLC campaign for the standalone ETP model."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "formal" / "tla"
MODEL = "EffectTransaction.tla"
CONFIG = "EffectTransaction.cfg"
TLA2TOOLS_VERSION = "v1.7.4"
TLC_VERSION = "2.19"
TLA2TOOLS_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
EXPECTED_GENERATED = 309_556
EXPECTED_DISTINCT = 65_232
EXPECTED_DEPTH = 18
RESULT_PATH = MODEL_DIR / "result.json"

STATE_COUNTS = re.compile(
    r"(?m)^(\d+) states generated, (\d+) distinct states found, 0 states left on queue\.\s*$"
)
DEPTH = re.compile(r"(?m)^The depth of the complete state graph search is (\d+)\.\s*$")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_jar(argument: Path | None) -> Path:
    candidates: list[Path] = []
    if argument is not None:
        candidates.append(argument)
    environment = os.environ.get("TLA2TOOLS_JAR")
    if environment:
        candidates.append(Path(environment))
    candidates.append(ROOT / ".local" / "tools" / "tla2tools.jar")
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if resolved.is_file():
            return resolved
    raise FileNotFoundError(
        "TLC jar not found; run tools/fetch-tla2tools.py or pass --jar"
    )


def _parse_result(output: str) -> tuple[int, int, int]:
    counts = STATE_COUNTS.search(output)
    depth = DEPTH.search(output)
    if counts is None or depth is None:
        raise ValueError("TLC output does not contain the complete-search counters")
    return int(counts.group(1)), int(counts.group(2)), int(depth.group(1))


def _result_document(generated: int, distinct: int, depth: int, jar_hash: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "model": "EffectTransaction",
        "configuration": {
            "MaxTime": 3,
            "MaxEpoch": 2,
            "MaxReconciliations": 3,
            "model_workers": 2,
            "tlc_worker_threads": 1,
        },
        "inputs": {
            "model_sha256": _sha256(MODEL_DIR / MODEL),
            "config_sha256": _sha256(MODEL_DIR / CONFIG),
            "tla2tools_version": TLA2TOOLS_VERSION,
            "tlc_version": TLC_VERSION,
            "tla2tools_sha256": jar_hash,
        },
        "result": {
            "status": "pass",
            "complete_bounded_search": True,
            "generated_states": generated,
            "distinct_states": distinct,
            "depth": depth,
            "states_left_on_queue": 0,
        },
        "boundary": (
            "Bounded model checking is not an implementation refinement proof "
            "or an unbounded liveness proof."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jar", type=Path, help="path to the pinned tla2tools.jar")
    arguments = parser.parse_args()

    try:
        jar = _resolve_jar(arguments.jar)
        observed_hash = _sha256(jar)
        if observed_hash != TLA2TOOLS_SHA256:
            raise ValueError(
                "TLC jar SHA-256 mismatch: "
                f"expected={TLA2TOOLS_SHA256} observed={observed_hash}"
            )
        java = shutil.which("java")
        if java is None:
            raise FileNotFoundError("java is not available on PATH")

        with tempfile.TemporaryDirectory(prefix="etp-tlc-") as metadata_directory:
            command = [
                java,
                "-XX:+UseParallelGC",
                "-jar",
                str(jar),
                "-workers",
                "1",
                "-metadir",
                metadata_directory,
                "-config",
                CONFIG,
                MODEL,
            ]
            completed = subprocess.run(
                command,
                cwd=MODEL_DIR,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        output = completed.stdout + completed.stderr
        print(output, end="" if output.endswith("\n") else "\n")
        if completed.returncode != 0:
            raise RuntimeError(f"TLC exited with status {completed.returncode}")
        if f"TLC2 Version {TLC_VERSION} " not in output:
            raise ValueError(f"unexpected TLC version; expected {TLC_VERSION}")
        if "Model checking completed. No error has been found." not in output:
            raise ValueError("TLC did not report a successful complete search")

        generated, distinct, depth = _parse_result(output)
        observed = (generated, distinct, depth)
        expected = (EXPECTED_GENERATED, EXPECTED_DISTINCT, EXPECTED_DEPTH)
        if observed != expected:
            raise ValueError(f"unexpected state-space counters: expected={expected} observed={observed}")

        result_document = _result_document(generated, distinct, depth, observed_hash)
        RESULT_PATH.write_text(
            json.dumps(result_document, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"FAIL tla_model_check: {error}", file=sys.stderr)
        return 1

    print(
        "PASS tla_model_check "
        f"models=1 generated={generated} distinct={distinct} depth={depth} "
        f"tla2tools={TLA2TOOLS_VERSION} sha256={observed_hash}"
    )
    print("BOUNDARY bounded model checking is not an implementation refinement proof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

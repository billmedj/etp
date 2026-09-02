#!/usr/bin/env python3
"""Build and verify the deterministic public evidence index for ETP."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "evidence-summary.json"
LEAN_MODEL = ROOT / "formal" / "lean" / "ETPFormal" / "EffectTransaction.lean"
LEAN_THEOREM = re.compile(r"(?m)^\s*theorem\s+[A-Za-z0-9_']+")

EXPECTED_CONFORMANCE_CATEGORIES = {
    "binding": 30,
    "canonicalization": 7,
    "chain": 2,
    "claim": 3,
    "currentness": 6,
    "issuance": 2,
    "receipt": 8,
    "reconciliation": 5,
    "time": 3,
    "transport": 11,
}
EXPECTED_PROFILE_DESCRIPTORS = {
    "http-conditional-0.1.profile.json",
    "kubernetes-json-patch-0.1.profile.json",
}
EXPECTED_PROFILE_OUTCOMES = {
    "http-conditional-0.1.json": {
        "existing-put-with-strong-etag": "unknown",
        "create-only-put": "succeeded",
    },
    "kubernetes-json-patch-0.1.json": {
        "namespaced-deployment-replica-change": "unknown",
        "status-subresource-change": "succeeded",
    },
}
EXPECTED_TLA_RESULT = {
    "generated_states": 309_556,
    "distinct_states": 65_232,
    "depth": 18,
}
TLA2TOOLS_VERSION = "v1.7.4"
TLC_VERSION = "2.19"
TLA2TOOLS_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"

VECTOR_MIRRORS = (
    (
        "vectors/authority-cose-sign1-ed25519-0.1.json",
        "crates/effect-transaction-authority/test-vectors/authority-cose-sign1-ed25519-0.1.json",
    ),
    (
        "vectors/positive-chain.json",
        "crates/effect-transaction-core/test-vectors/positive-chain.json",
    ),
    (
        "vectors/positive-not-dispatched.json",
        "crates/effect-transaction-core/test-vectors/positive-not-dispatched.json",
    ),
    (
        "vectors/canonicalization.json",
        "crates/effect-transaction-core/test-vectors/canonicalization.json",
    ),
    (
        "vectors/negative-chains.json",
        "crates/effect-transaction-core/test-vectors/negative-chains.json",
    ),
    (
        "vectors/positive-chain.json",
        "crates/effect-transaction-cli/test-vectors/positive-chain.json",
    ),
)


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_no_duplicates)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _set_sha256(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        if not path.is_file():
            raise ValueError(f"missing evidence input: {path.relative_to(ROOT).as_posix()}")
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(bytes.fromhex(_sha256(path)))
        digest.update(b"\0")
    return digest.hexdigest()


def _require_count(label: str, observed: int, expected: int) -> None:
    if observed != expected:
        raise ValueError(f"{label}: expected={expected} observed={observed}")


def _check_vector_mirrors() -> list[Path]:
    paths: list[Path] = []
    for published_relative, implementation_relative in VECTOR_MIRRORS:
        published = ROOT / published_relative
        implementation = ROOT / implementation_relative
        if not published.is_file() or not implementation.is_file():
            raise ValueError(
                "missing vector mirror: "
                f"{published_relative} or {implementation_relative}"
            )
        if published.read_bytes() != implementation.read_bytes():
            raise ValueError(
                "implementation vector differs from its public source: "
                f"{implementation_relative} != {published_relative}"
            )
        paths.extend([published, implementation])
    return paths


def _core_schema_evidence() -> tuple[dict[str, int], list[Path]]:
    schema_paths = sorted((ROOT / "schemas").glob("*.schema.json"))
    _require_count("core schemas", len(schema_paths), 9)
    envelope_names = {
        "test-vector-envelope-0.1.schema.json",
        "transaction-bundle-0.1.schema.json",
    }
    envelope_count = sum(path.name in envelope_names for path in schema_paths)
    _require_count("core envelope schemas", envelope_count, 2)
    oracle_paths = [
        ROOT / "profiles" / "validate-core-bundle-schemas.mjs",
        ROOT / "profiles" / "package.json",
        ROOT / "profiles" / "package-lock.json",
        ROOT / "vectors" / "positive-chain.json",
        ROOT / "vectors" / "positive-not-dispatched.json",
    ]
    _set_sha256(schema_paths + oracle_paths)
    return {
        "strict_schemas": len(schema_paths),
        "envelope_schemas": envelope_count,
    }, schema_paths + oracle_paths


def _profile_evidence() -> tuple[dict[str, int], list[Path]]:
    descriptor_paths = sorted((ROOT / "profiles").glob("*.profile.json"))
    observed_descriptors = {path.name for path in descriptor_paths}
    if observed_descriptors != EXPECTED_PROFILE_DESCRIPTORS:
        raise ValueError(
            "profile descriptors differ: "
            f"expected={sorted(EXPECTED_PROFILE_DESCRIPTORS)} "
            f"observed={sorted(observed_descriptors)}"
        )

    schema_paths: set[Path] = set()
    for descriptor_path in descriptor_paths:
        descriptor = _load(descriptor_path)
        schemas = descriptor.get("schemas")
        if not isinstance(schemas, dict):
            raise ValueError(f"invalid schemas map: {descriptor_path.relative_to(ROOT)}")
        for relative in schemas.values():
            if not isinstance(relative, str):
                raise ValueError(f"invalid schema path: {descriptor_path.relative_to(ROOT)}")
            schema_paths.add(descriptor_path.parent / relative)
    _require_count("registered profile schemas", len(schema_paths), 14)
    for path in schema_paths:
        if not path.is_file():
            raise ValueError(f"missing registered profile schema: {path.relative_to(ROOT)}")

    vector_paths = sorted((ROOT / "vectors" / "profiles").glob("*.json"))
    _require_count("profile vector documents", len(vector_paths), 2)
    positive = 0
    adversarial = 0
    for path in vector_paths:
        vector = _load(path)
        positive_cases = vector.get("positive")
        adversarial_cases = vector.get("adversarial")
        if not isinstance(positive_cases, list) or not isinstance(adversarial_cases, list):
            raise ValueError(f"invalid profile vector document: {path.relative_to(ROOT)}")
        observed_outcomes: dict[str, str] = {}
        for case in positive_cases:
            name = case.get("name")
            outcome = case.get("expected_receipt_outcome")
            documents = case.get("documents")
            if not isinstance(name, str) or outcome not in {"succeeded", "unknown"}:
                raise ValueError(f"invalid positive profile vector: {path.relative_to(ROOT)}")
            if not isinstance(documents, dict):
                raise ValueError(f"missing profile documents: {path.relative_to(ROOT)}::{name}")
            has_reconciliation = "reconciliation_evidence" in documents
            if (outcome == "unknown") != has_reconciliation:
                raise ValueError(
                    "profile reconciliation must exist if and only if the expected "
                    f"receipt is unknown: {path.relative_to(ROOT)}::{name}"
                )
            observation = documents.get("observation_evidence")
            if not isinstance(observation, dict):
                raise ValueError(f"missing observation evidence: {path.relative_to(ROOT)}::{name}")
            allowed_transport = (
                {"lost", "unverifiable"} if outcome == "unknown" else {"response"}
            )
            if observation.get("transport_outcome") not in allowed_transport:
                raise ValueError(
                    f"profile transport outcome differs: {path.relative_to(ROOT)}::{name}"
                )
            observed_outcomes[name] = outcome
        if observed_outcomes != EXPECTED_PROFILE_OUTCOMES.get(path.name):
            raise ValueError(
                f"profile receipt outcomes differ: {path.relative_to(ROOT)} "
                f"observed={observed_outcomes}"
            )
        zero_digest_cases = [
            case for case in adversarial_cases
            if case.get("name") == "reject-all-zero-digest"
            and case.get("expect_code") == "PROFILE_SCHEMA"
        ]
        _require_count(f"all-zero digest vectors in {path.name}", len(zero_digest_cases), 1)
        positive += len(positive_cases)
        adversarial += len(adversarial_cases)
    _require_count("positive profile vectors", positive, 4)
    _require_count("adversarial profile vectors", adversarial, 46)

    oracle_paths = [
        ROOT / "profiles" / "validate-reference-profiles.mjs",
        ROOT / "profiles" / "package.json",
        ROOT / "profiles" / "package-lock.json",
    ]
    all_paths = vector_paths + descriptor_paths + sorted(schema_paths) + oracle_paths
    _set_sha256(all_paths)
    return {
        "descriptors": len(descriptor_paths),
        "positive_vectors": positive,
        "adversarial_vectors": adversarial,
        "total_vectors": positive + adversarial,
        "registered_document_schemas": len(schema_paths),
    }, all_paths


def _conformance_evidence() -> tuple[dict[str, Any], list[Path]]:
    manifest_path = ROOT / "conformance" / "manifest.json"
    manifest = _load(manifest_path)
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise ValueError("conformance manifest has no cases array")
    _require_count("conformance cases", len(cases), 77)
    categories = dict(sorted(Counter(case["category"] for case in cases).items()))
    if categories != EXPECTED_CONFORMANCE_CATEGORIES:
        raise ValueError(
            "conformance categories differ: "
            f"expected={EXPECTED_CONFORMANCE_CATEGORIES} observed={categories}"
        )
    paths = [
        manifest_path,
        ROOT / "conformance" / "runner.ts",
        ROOT / "conformance" / "trace.schema.json",
        ROOT / "vectors" / "conformance-mutations.json",
        ROOT / "vectors" / "conformance-traces.json",
        ROOT / "vectors" / "positive-chain.json",
        ROOT / "vectors" / "positive-not-dispatched.json",
        *sorted((ROOT / "typescript" / "src").glob("*.ts")),
    ]
    _set_sha256(paths)
    return {"cases": len(cases), "categories": categories}, paths


def _authority_evidence() -> tuple[dict[str, int], list[Path]]:
    vectors = sorted((ROOT / "vectors").glob("authority-*.json"))
    _require_count("authority vectors", len(vectors), 1)
    paths = vectors + [
        ROOT / "profiles" / "authority-cose-sign1-ed25519-0.1.md",
        ROOT / "profiles" / "authority-cose-sign1-ed25519-0.1.schema.json",
    ]
    _set_sha256(paths)
    return {"vectors": len(vectors)}, paths


def _lean_evidence() -> tuple[dict[str, int], list[Path]]:
    source = LEAN_MODEL.read_text(encoding="utf-8")
    theorem_count = len(LEAN_THEOREM.findall(source))
    _require_count("Lean theorems", theorem_count, 23)
    paths = [
        LEAN_MODEL,
        ROOT / "formal" / "lean" / "ETPFormal.lean",
        ROOT / "formal" / "lean" / "lakefile.toml",
        ROOT / "formal" / "lean" / "lake-manifest.json",
        ROOT / "formal" / "lean" / "lean-toolchain",
        ROOT / "tools" / "check-lean.py",
    ]
    _set_sha256(paths)
    return {"sources": 1, "theorems": theorem_count}, paths


def _tla_evidence() -> tuple[dict[str, int], list[Path]]:
    model_path = ROOT / "formal" / "tla" / "EffectTransaction.tla"
    config_path = ROOT / "formal" / "tla" / "EffectTransaction.cfg"
    result_path = ROOT / "formal" / "tla" / "result.json"
    expected_result = {
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
            "model_sha256": _sha256(model_path),
            "config_sha256": _sha256(config_path),
            "tla2tools_version": TLA2TOOLS_VERSION,
            "tlc_version": TLC_VERSION,
            "tla2tools_sha256": TLA2TOOLS_SHA256,
        },
        "result": {
            "status": "pass",
            "complete_bounded_search": True,
            **EXPECTED_TLA_RESULT,
            "states_left_on_queue": 0,
        },
        "boundary": (
            "Bounded model checking is not an implementation refinement proof "
            "or an unbounded liveness proof."
        ),
    }
    if _load(result_path) != expected_result:
        raise ValueError("formal/tla/result.json does not match the configured model and result")
    paths = [
        model_path,
        config_path,
        result_path,
        ROOT / "tools" / "fetch-tla2tools.py",
        ROOT / "tools" / "run-tla.py",
    ]
    _set_sha256(paths)
    return {"models": 1}, paths


def _implementation_evidence() -> tuple[dict[str, int], list[Path]]:
    rust_sources = sorted((ROOT / "crates").rglob("*.rs"))
    cargo_manifests = [ROOT / "Cargo.toml", *sorted((ROOT / "crates").glob("*/Cargo.toml"))]
    rust_paths = rust_sources + cargo_manifests + [
        ROOT / "Cargo.lock",
        ROOT / "rust-toolchain.toml",
    ]
    typescript_sources = sorted((ROOT / "typescript").rglob("*.ts"))
    typescript_paths = typescript_sources + [
        ROOT / "typescript" / "package.json",
        ROOT / "typescript" / "package-lock.json",
        ROOT / "typescript" / "tsconfig.json",
    ]
    _set_sha256(rust_paths)
    _set_sha256(typescript_paths)
    return {
        "rust_crates": len(cargo_manifests) - 1,
        "rust_source_files": len(rust_sources),
        "typescript_source_and_test_files": len(typescript_sources),
    }, rust_paths + typescript_paths


def build_summary() -> dict[str, Any]:
    mirror_paths = _check_vector_mirrors()
    core_counts, core_paths = _core_schema_evidence()
    profile_counts, profile_paths = _profile_evidence()
    conformance_counts, conformance_paths = _conformance_evidence()
    authority_counts, authority_paths = _authority_evidence()
    lean_counts, lean_paths = _lean_evidence()
    tla_counts, tla_paths = _tla_evidence()
    implementation_counts, implementation_paths = _implementation_evidence()

    return {
        "schema_version": 1,
        "protocol_profile": "effect-transaction/core/0.1",
        "status": "implementer-draft",
        "counts": {
            "authority": authority_counts,
            "conformance": conformance_counts,
            "core_schemas": core_counts,
            "effect_profiles": profile_counts,
            "implementations": implementation_counts,
            "lean": lean_counts,
            "tla": tla_counts,
        },
        "source_set_sha256": {
            "authority_profile": _set_sha256(authority_paths),
            "conformance_contracts_and_oracle": _set_sha256(conformance_paths),
            "core_schema_contracts_and_oracle": _set_sha256(core_paths),
            "effect_profile_contracts_and_oracle": _set_sha256(profile_paths),
            "implementation_sources": _set_sha256(implementation_paths + mirror_paths),
            "lean_model_and_build_inputs": _set_sha256(lean_paths),
            "tla_model_config_and_runner": _set_sha256(tla_paths),
        },
        "tla_observation": {
            "model": "EffectTransaction",
            "configuration": {
                "MaxTime": 3,
                "MaxEpoch": 2,
                "MaxReconciliations": 3,
                "model_workers": 2,
                "tlc_worker_threads": 1,
            },
            "tla2tools_version": TLA2TOOLS_VERSION,
            "tlc_version": TLC_VERSION,
            "tla2tools_sha256": TLA2TOOLS_SHA256,
            "result": EXPECTED_TLA_RESULT,
            "scope": "complete bounded search for the configured model",
            "boundary": (
                "bounded model checking; not an implementation refinement proof "
                "or an unbounded liveness proof"
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print", action="store_true", dest="print_summary")
    arguments = parser.parse_args()
    try:
        observed = build_summary()
        if arguments.print_summary:
            print(json.dumps(observed, indent=2, sort_keys=True, ensure_ascii=True))
            return 0
        expected = _load(SUMMARY)
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"FAIL evidence_index: {error}", file=sys.stderr)
        return 1

    if observed != expected:
        print("FAIL evidence_index: evidence-summary.json is stale", file=sys.stderr)
        print(json.dumps(observed, indent=2, sort_keys=True, ensure_ascii=True), file=sys.stderr)
        return 1
    print(
        "PASS evidence_index "
        f"cases={observed['counts']['conformance']['cases']} "
        f"profile_vectors={observed['counts']['effect_profiles']['total_vectors']} "
        f"lean_theorems={observed['counts']['lean']['theorems']} "
        f"tla_models={observed['counts']['tla']['models']}"
    )
    print("BOUNDARY recorded TLC counters must be reproduced with tools/run-tla.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

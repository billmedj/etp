from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "check-evidence.py"
SPEC = importlib.util.spec_from_file_location("check_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvidenceTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            json.loads('{"key":1,"key":2}', object_pairs_hook=MODULE._pairs_no_duplicates)

    def test_public_evidence_counts_are_exact(self) -> None:
        summary = MODULE.build_summary()
        self.assertEqual(summary["counts"]["conformance"]["cases"], 77)
        self.assertEqual(summary["counts"]["effect_profiles"]["total_vectors"], 50)
        self.assertEqual(summary["counts"]["effect_profiles"]["positive_vectors"], 4)
        self.assertEqual(summary["counts"]["effect_profiles"]["adversarial_vectors"], 46)
        self.assertEqual(summary["counts"]["lean"], {"sources": 1, "theorems": 23})
        self.assertEqual(summary["counts"]["tla"], {"models": 1})

    def test_profile_receipt_lifecycle_is_explicit(self) -> None:
        for name, expected in MODULE.EXPECTED_PROFILE_OUTCOMES.items():
            suite = MODULE._load(ROOT / "vectors" / "profiles" / name)
            observed = {
                vector["name"]: vector["expected_receipt_outcome"]
                for vector in suite["positive"]
            }
            self.assertEqual(observed, expected)
            for vector in suite["positive"]:
                documents = vector["documents"]
                outcome = vector["expected_receipt_outcome"]
                self.assertEqual("reconciliation_evidence" in documents, outcome == "unknown")
                transport = documents["observation_evidence"]["transport_outcome"]
                if outcome == "unknown":
                    self.assertIn(transport, {"lost", "unverifiable"})
                else:
                    self.assertEqual(transport, "response")

    def test_checked_in_summary_matches_sources(self) -> None:
        expected = MODULE._load(ROOT / "evidence-summary.json")
        self.assertEqual(MODULE.build_summary(), expected)


if __name__ == "__main__":
    unittest.main()

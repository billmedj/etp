from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "check-language.py"
SPEC = importlib.util.spec_from_file_location("check_language", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LanguageTests(unittest.TestCase):
    def test_clean_text_passes(self) -> None:
        findings = MODULE.check_text(
            Path("sample.md"),
            "# Test\n\nThe executor rejects a stale grant.\n",
            "sample.md",
        )
        self.assertEqual(findings, [])

    def test_private_path_fails(self) -> None:
        private_path = "C:\\" + "Users\\private\\source"
        findings = MODULE.check_text(
            Path("sample.md"),
            f"Build from {private_path}.\n",
            "sample.md",
        )
        self.assertTrue(any("private local path" in item for item in findings))

    def test_product_scope_fails(self) -> None:
        product_name = "Accord" + "Lock"
        findings = MODULE.check_text(
            Path("sample.md"),
            f"This module is part of {product_name}.\n",
            "sample.md",
        )
        self.assertTrue(any("product-specific scope" in item for item in findings))

    def test_research_scope_fails(self) -> None:
        research_term = "seman" + "timeter"
        findings = MODULE.check_text(
            Path("sample.md"),
            f"This module implements the {research_term}.\n",
            "sample.md",
        )
        self.assertTrue(any("external research scope" in item for item in findings))

    def test_promotional_wording_fails(self) -> None:
        restricted_word = "revo" + "lutionary"
        findings = MODULE.check_text(
            Path("sample.md"),
            f"This is a {restricted_word} protocol.\n",
            "sample.md",
        )
        self.assertTrue(any("promotional wording" in item for item in findings))

    def test_formulaic_filler_fails(self) -> None:
        restricted_phrase = "at its " + "core"
        findings = MODULE.check_text(
            Path("sample.md"),
            f"{restricted_phrase}, the protocol changes execution.\n",
            "sample.md",
        )
        self.assertTrue(any("formulaic filler" in item for item in findings))

    def test_non_ascii_markdown_fails(self) -> None:
        findings = MODULE.check_text(
            Path("sample.md"),
            "Use a typographic apostrophe: it\u2019s.\n",
            "sample.md",
        )
        self.assertTrue(any("ASCII" in item for item in findings))

    def test_language_guide_can_name_style_terms(self) -> None:
        restricted_word = "bullet" + "proof"
        findings = MODULE.check_text(
            Path("LANGUAGE.md"),
            f"Do not claim that a component is {restricted_word}.\n",
            "LANGUAGE.md",
        )
        self.assertEqual(findings, [])

    def test_language_guide_cannot_name_external_product(self) -> None:
        product_name = "Accord" + "Lock"
        findings = MODULE.check_text(
            Path("LANGUAGE.md"),
            f"Do not refer to {product_name}.\n",
            "LANGUAGE.md",
        )
        self.assertTrue(any("product-specific scope" in item for item in findings))


if __name__ == "__main__":
    unittest.main()

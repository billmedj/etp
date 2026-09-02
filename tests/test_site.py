from __future__ import annotations

import binascii
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "check-site.py"
SPEC = importlib.util.spec_from_file_location("check_site", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


DESCRIPTION = (
    "ETP defines records and executor rules for external actions proposed by "
    "untrusted agents, from authorization through outcome reconciliation."
)


def _png_header(width: int, height: int) -> bytes:
    data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    chunk = b"IHDR" + data
    return (
        MODULE.PNG_SIGNATURE
        + struct.pack(">I", len(data))
        + chunk
        + struct.pack(">I", binascii.crc32(chunk) & 0xFFFFFFFF)
    )


def _write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def _valid_summary() -> dict[str, object]:
    return {
        "status": "implementer-draft",
        "counts": {
            "conformance": {"cases": 77},
            "effect_profiles": {"total_vectors": 50},
            "lean": {"theorems": 23},
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
            "tla2tools_version": "v1.7.4",
            "tlc_version": "2.19",
            "tla2tools_sha256": "a" * 64,
            "result": {
                "generated_states": 309556,
                "distinct_states": 65232,
                "depth": 18,
            },
        },
    }


def _valid_tla() -> dict[str, object]:
    summary = _valid_summary()["tla_observation"]
    assert isinstance(summary, dict)
    return {
        "model": summary["model"],
        "configuration": summary["configuration"],
        "inputs": {
            "tla2tools_version": summary["tla2tools_version"],
            "tlc_version": summary["tlc_version"],
            "tla2tools_sha256": summary["tla2tools_sha256"],
        },
        "result": {
            **summary["result"],
            "status": "pass",
            "complete_bounded_search": True,
            "states_left_on_queue": 0,
        },
    }


def _valid_html(extra_head: str = "", extra_body: str = "") -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{DESCRIPTION}">
  <meta name="theme-color" content="#f4f1e9">
  <meta property="og:type" content="website">
  <meta property="og:title" content="Effect Transaction Protocol">
  <meta property="og:description" content="{DESCRIPTION}">
  <meta property="og:url" content="{MODULE.PUBLIC_BASE}">
  <meta property="og:image" content="{MODULE.PUBLIC_BASE}assets/social-card.png">
  <meta property="og:image:type" content="image/png">
  <meta property="og:image:width" content="1280">
  <meta property="og:image:height" content="640">
  <meta property="og:image:alt" content="ETP reference transaction">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="Effect Transaction Protocol">
  <meta name="twitter:description" content="{DESCRIPTION}">
  <meta name="twitter:image" content="{MODULE.PUBLIC_BASE}assets/social-card.png">
  <meta name="twitter:image:alt" content="ETP reference transaction">
  <link rel="canonical" href="{MODULE.PUBLIC_BASE}">
  <link rel="icon" href="./assets/etp-mark.svg">
  <link rel="apple-touch-icon" href="./assets/apple-touch-icon.png">
  <style>@font-face {{ src: url('./assets/fonts/test.woff2'); }}</style>
  <title>Effect Transaction Protocol</title>
  {extra_head}
</head>
<body>
  <header><nav aria-label="Primary"><a href="#main">Skip</a></nav></header>
  <main id="main">
    <h1>Effect Transaction Protocol</h1>
    <p>77 Core conformance cases</p>
    <p>50 Effect-profile vectors</p>
    <p>23 Lean theorem declarations</p>
    <p>65,232 Distinct bounded TLA+ states</p>
    <p>Core 0.1 is an implementer draft.</p>
    <p>Passing these checks does not certify a deployment or establish ecosystem interoperability.</p>
    {extra_body}
  </main>
  <footer>ETP Core 0.1</footer>
</body>
</html>
"""


def _write_valid_site(root: Path) -> None:
    (root / ".nojekyll").write_text("", encoding="utf-8")
    (root / "assets" / "fonts").mkdir(parents=True)
    (root / "assets" / "fonts" / "test.woff2").write_bytes(b"font")
    (root / "assets" / "etp-mark.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"/>',
        encoding="utf-8",
    )
    (root / "assets" / "social-card.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"><style>'
        '@font-face { src: url("fonts/test.woff2"); }</style></svg>',
        encoding="utf-8",
    )
    (root / "assets" / "social-card.png").write_bytes(_png_header(1280, 640))
    (root / "assets" / "apple-touch-icon.png").write_bytes(_png_header(180, 180))
    (root / "index.html").write_text(_valid_html(), encoding="utf-8")
    _write_json(root / "evidence-summary.json", _valid_summary())
    _write_json(root / "formal" / "tla" / "result.json", _valid_tla())


class SiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        _write_valid_site(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_site_passes(self) -> None:
        self.assertEqual(MODULE.check_site(self.root), [])

    def test_missing_social_metadata_fails(self) -> None:
        html = (self.root / "index.html").read_text(encoding="utf-8")
        html = html.replace('<meta property="og:image:alt" content="ETP reference transaction">\n', "")
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("og:image:alt" in finding for finding in findings))

    def test_mismatched_social_titles_fail(self) -> None:
        html = (self.root / "index.html").read_text(encoding="utf-8")
        html = html.replace(
            '<meta name="twitter:title" content="Effect Transaction Protocol">',
            '<meta name="twitter:title" content="Different title">',
        )
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("titles must match" in finding for finding in findings))

    def test_root_relative_url_fails(self) -> None:
        html = _valid_html(extra_body='<img src="/assets/social-card.png" alt="">')
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("root-relative URL" in finding for finding in findings))

    def test_missing_local_asset_fails(self) -> None:
        html = _valid_html(extra_body='<img src="./assets/missing.png" alt="">')
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("missing local target" in finding for finding in findings))

    def test_stale_public_metric_fails(self) -> None:
        html = (self.root / "index.html").read_text(encoding="utf-8")
        html = html.replace("77 Core conformance cases", "76 Core conformance cases")
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("conformance.cases=77" in finding for finding in findings))

    def test_tla_summary_mismatch_fails(self) -> None:
        tla = _valid_tla()
        result = tla["result"]
        assert isinstance(result, dict)
        result["distinct_states"] = 65231
        _write_json(self.root / "formal" / "tla" / "result.json", tla)
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("TLA evidence mismatch" in finding for finding in findings))

    def test_wrong_png_dimensions_fail(self) -> None:
        (self.root / "assets" / "social-card.png").write_bytes(_png_header(1200, 630))
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("expected dimensions" in finding for finding in findings))

    def test_missing_implementer_draft_boundary_fails(self) -> None:
        html = (self.root / "index.html").read_text(encoding="utf-8")
        html = html.replace("Core 0.1 is an implementer draft.", "Core 0.1.")
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("implementer draft" in finding for finding in findings))

    def test_missing_nojekyll_fails(self) -> None:
        (self.root / ".nojekyll").unlink()
        self.assertIn("missing .nojekyll", MODULE.check_site(self.root))

    def test_duplicate_theme_color_fails(self) -> None:
        html = _valid_html(extra_head='<meta name="theme-color" content="#ffffff">')
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("theme-color" in finding and "exactly once" in finding for finding in findings))

    def test_missing_landmark_fails(self) -> None:
        html = (self.root / "index.html").read_text(encoding="utf-8")
        html = html.replace("<footer>ETP Core 0.1</footer>", "")
        (self.root / "index.html").write_text(html, encoding="utf-8")
        self.assertIn("the document must contain a <footer> landmark", MODULE.check_site(self.root))

    def test_multiple_h1_elements_fail(self) -> None:
        html = _valid_html(extra_body="<h1>Second title</h1>")
        (self.root / "index.html").write_text(html, encoding="utf-8")
        self.assertIn("the document must contain exactly one <h1>", MODULE.check_site(self.root))

    def test_heading_level_jump_fails(self) -> None:
        html = _valid_html(extra_body="<h3>Skipped level</h3>")
        (self.root / "index.html").write_text(html, encoding="utf-8")
        self.assertIn("heading hierarchy skips from h1 to h3", MODULE.check_site(self.root))

    def test_duplicate_id_fails(self) -> None:
        html = _valid_html(extra_body='<p id="main">Duplicate</p>')
        (self.root / "index.html").write_text(html, encoding="utf-8")
        self.assertIn("duplicate HTML ids: main", MODULE.check_site(self.root))

    def test_image_without_intrinsic_attributes_fails(self) -> None:
        html = _valid_html(extra_body='<img src="./assets/social-card.png">')
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("declare alt text" in finding for finding in findings))
        self.assertTrue(any("positive integer width" in finding for finding in findings))
        self.assertTrue(any("positive integer height" in finding for finding in findings))

    def test_local_human_document_link_fails(self) -> None:
        (self.root / "SPEC.md").write_text("# Specification", encoding="utf-8")
        html = _valid_html(extra_body='<a href="./SPEC.md">Read the specification</a>')
        (self.root / "index.html").write_text(html, encoding="utf-8")
        findings = MODULE.check_site(self.root)
        self.assertTrue(any("must use their GitHub URL" in finding for finding in findings))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "tools" / "source-manifest.py"
SPEC = importlib.util.spec_from_file_location("etp_source_manifest", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class SourceManifestTests(unittest.TestCase):
    def test_archive_fallback_excludes_generated_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text("", encoding="utf-8")
            (root / "SOURCE_MANIFEST.sha256").write_text("", encoding="utf-8")
            for relative in (
                "target/generated.bin",
                "__pycache__/cached.pyc",
                ".lake/build/generated.c",
                ".local/tools/tool.jar",
                "node_modules/package/index.js",
                "formal/tla/states/19-0/states_0",
            ):
                generated = root / relative
                generated.parent.mkdir(parents=True, exist_ok=True)
                generated.write_text("generated\n", encoding="utf-8")
            self.assertEqual(
                CHECKER.repository_paths(root, "must-not-be-invoked"),
                ["src/lib.rs"],
            )

    def test_entries_are_sorted_and_hash_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "z.txt").write_bytes(b"z\r\n")
            (root / "a.txt").write_bytes(b"a\n")
            entries = CHECKER.build_entries(root, ["z.txt", "a.txt"])
        self.assertEqual([entry[0] for entry in entries], ["a.txt", "z.txt"])
        self.assertEqual(len(entries[0][1]), 64)

    def test_duplicate_or_unsorted_manifest_fails(self) -> None:
        digest = "a" * 64
        for text in (
            f"{digest}  z.txt\n{digest}  a.txt\n",
            f"{digest}  a.txt\n{digest}  a.txt\n",
        ):
            with self.subTest(text=text), self.assertRaises(CHECKER.ManifestError):
                CHECKER.parse_manifest(text)

    def test_malformed_or_escaping_path_fails(self) -> None:
        with self.assertRaises(CHECKER.ManifestError):
            CHECKER.parse_manifest("not-a-digest  a.txt\n")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(CHECKER.ManifestError):
                CHECKER.build_entries(root, ["../outside.txt"])

    def test_rust_include_must_be_literal_and_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "src" / "lib.rs"
            source.parent.mkdir()
            included = root / "data.txt"
            included.write_text("bound", encoding="utf-8")
            source.write_text(
                'const DATA: &str = include_str!("../data.txt");\n', encoding="utf-8"
            )
            self.assertEqual(
                CHECKER.validate_rust_compiler_inputs(root, ["src/lib.rs", "data.txt"]),
                1,
            )
            with self.assertRaises(CHECKER.ManifestError):
                CHECKER.validate_rust_compiler_inputs(root, ["src/lib.rs"])
            source.write_text(
                'const DATA: &str = include_str!(concat!("..", "/data.txt"));\n',
                encoding="utf-8",
            )
            with self.assertRaises(CHECKER.ManifestError):
                CHECKER.validate_rust_compiler_inputs(root, ["src/lib.rs", "data.txt"])

    def test_dep_info_parser_preserves_windows_slashes_and_escaped_spaces(self) -> None:
        parsed = CHECKER.parse_dep_info(
            "C:\\repo\\target\\x.d: C:\\repo\\src\\lib.rs "
            "C:\\repo\\with\\ escaped.rs\n"
        )
        self.assertEqual(parsed, [r"C:\repo\src\lib.rs", r"C:\repo\with escaped.rs"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Check public repository text for private data and restricted wording."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".cfg",
    ".cff",
    ".json",
    ".lean",
    ".lock",
    ".md",
    ".mjs",
    ".py",
    ".rs",
    ".sh",
    ".tla",
    ".toml",
    ".ts",
    ".txt",
    ".yml",
    ".yaml",
}
TEXT_NAMES = {"LICENSE", "NOTICE", ".editorconfig", ".gitattributes", ".gitignore"}
SKIP_PARTS = {
    ".git",
    ".lake",
    ".local",
    ".pytest_cache",
    "__pycache__",
    "coverage",
    "dist",
    "node_modules",
    "target",
}


class Rule(NamedTuple):
    label: str
    pattern: re.Pattern[str]
    allowed_in_language_guide: bool = False


PRIVATE_ACCOUNT = "B-" + "Logy"
PRODUCT_NAME = "Accord" + "Lock"
RESEARCH_TERMS = (
    "CR" + "CS",
    "C" + "VT",
    "When" + "ce",
    "seman" + "timeter",
    "seman" + "timetre",
    "semantic" + " meter",
    "Qur" + "an",
)
PROMOTIONAL_TERMS = (
    "bullet" + "proof",
    "cutting" + "-edge",
    "game" + "-changing",
    "ground" + "breaking",
    "power" + "ful",
    "revo" + "lutionary",
    "seam" + "lessly",
    "world" + "-class",
)
AI_FILLER = (
    "in today's " + "fast-paced",
    "in the ever-" + "evolving",
    "more than " + "just",
    "not " + "just",
)


def _alternation(terms: tuple[str, ...]) -> str:
    return "|".join(re.escape(term) for term in terms)


RULES = (
    Rule(
        "private local path",
        re.compile(r"(?i)(?:[A-Z]:\\Users\\|\\\\\?\\[A-Z]:\\Users\\|/(?:Users|home)/)"),
    ),
    Rule("private local account", re.compile(rf"(?i)\b{re.escape(PRIVATE_ACCOUNT)}\b")),
    Rule("product-specific scope", re.compile(rf"(?i)\b{re.escape(PRODUCT_NAME)}\b")),
    Rule("external research scope", re.compile(rf"(?i)\b(?:{_alternation(RESEARCH_TERMS)})\b")),
    Rule(
        "promotional wording",
        re.compile(rf"(?i)\b(?:{_alternation(PROMOTIONAL_TERMS)})\b"),
        allowed_in_language_guide=True,
    ),
    Rule(
        "formulaic filler",
        re.compile(rf"(?i)\b(?:{_alternation(AI_FILLER)})\b"),
        allowed_in_language_guide=True,
    ),
    Rule("GitHub token", re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b")),
    Rule("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    Rule("private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)


def iter_files(root: Path = ROOT) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.relative_to(root).parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            files.append(path)
    return sorted(files)


def check_text(path: Path, text: str, relative: str) -> list[str]:
    """Return findings for one public text file."""

    findings: list[str] = []
    is_language_guide = relative == "LANGUAGE.md"
    for rule in RULES:
        if is_language_guide and rule.allowed_in_language_guide:
            continue
        for match in rule.pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{relative}:{line}: {rule.label}: {match.group(0)!r}")

    if path.suffix.lower() == ".md":
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(ord(character) > 127 for character in line):
                findings.append(
                    f"{relative}:{line_number}: public Markdown must use ASCII text and punctuation"
                )
    return findings


def main() -> int:
    findings: list[str] = []
    files = iter_files()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            findings.append(f"{path.relative_to(ROOT).as_posix()}: cannot read UTF-8 text: {error}")
            continue
        relative = path.relative_to(ROOT).as_posix()
        findings.extend(check_text(path, text, relative))

    if findings:
        print("FAIL public_language")
        for finding in findings:
            print(finding)
        return 1

    print(f"PASS public_language files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

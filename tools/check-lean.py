#!/usr/bin/env python3
"""Check the standalone Lean model for declared proof placeholders."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "formal" / "lean" / "ETPFormal" / "EffectTransaction.lean"
FORBIDDEN = re.compile(r"\b(?:sorry|axiom)\b")
THEOREM = re.compile(r"(?m)^\s*theorem\s+[A-Za-z_][A-Za-z0-9_']*")
EXPECTED_THEOREMS = 23


def main() -> int:
    try:
        text = MODEL.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"FAIL lean_source_policy: {error}", file=sys.stderr)
        return 1

    findings: list[str] = []
    for match in FORBIDDEN.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        findings.append(f"{MODEL.relative_to(ROOT).as_posix()}:{line}:{match.group(0)}")
    if findings:
        for finding in findings:
            print(f"FAIL lean_source_policy: forbidden declaration {finding}", file=sys.stderr)
        return 1

    theorem_count = len(THEOREM.findall(text))
    if theorem_count != EXPECTED_THEOREMS:
        print(
            "FAIL lean_source_policy: "
            f"expected_theorems={EXPECTED_THEOREMS} observed={theorem_count}",
            file=sys.stderr,
        )
        return 1

    print(
        "PASS lean_source_policy "
        f"sources=1 theorems={theorem_count} declared_axioms=0 placeholders=0"
    )
    print("BOUNDARY this source check does not replace `lake build`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

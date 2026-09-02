#!/usr/bin/env python3
"""Fetch the pinned TLC jar and accept it only after SHA-256 verification."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import urllib.request
from pathlib import Path


VERSION = "v1.7.4"
URL = f"https://github.com/tlaplus/tlaplus/releases/download/{VERSION}/tla2tools.jar"
SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".local/tools/tla2tools.jar"),
        help="destination for the verified jar",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.is_file():
        observed = file_sha256(output)
        if observed == SHA256:
            print(f"PASS tla2tools_cached version={VERSION} sha256={observed}")
            return 0
        print(
            "FAIL existing TLC jar has unexpected SHA-256: "
            f"path={output} expected={SHA256} observed={observed}",
            file=sys.stderr,
        )
        return 1

    descriptor, temporary_name = tempfile.mkstemp(
        prefix="tla2tools-", suffix=".jar", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with urllib.request.urlopen(URL, timeout=60) as response, temporary.open("wb") as handle:
            while chunk := response.read(1024 * 1024):
                handle.write(chunk)
        observed = file_sha256(temporary)
        if observed != SHA256:
            print(
                f"FAIL TLC jar SHA-256 mismatch: expected={SHA256} observed={observed}",
                file=sys.stderr,
            )
            return 1
        temporary.replace(output)
        print(f"PASS tla2tools_download version={VERSION} sha256={observed}")
        return 0
    except Exception as error:  # Network and file-system failures are fatal.
        print(f"FAIL tla2tools_download: {error}", file=sys.stderr)
        return 1
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())

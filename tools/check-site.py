#!/usr/bin/env python3
"""Validate the static ETP site and its published evidence references."""

from __future__ import annotations

import argparse
import binascii
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import struct
import sys
from typing import Any
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_BASE = "https://billmedj.github.io/etp/"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CSS_URL = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)", re.IGNORECASE)
SPACE = re.compile(r"\s+")
IMPLEMENTER_DRAFT = re.compile(r"\bimplementer[ -]draft\b", re.IGNORECASE)
DEPLOYMENT_BOUNDARY = re.compile(
    r"\b(?:does not certify|is not|not)\b.{0,100}\b(?:deployment|production)\b",
    re.IGNORECASE,
)
ECOSYSTEM_BOUNDARY = re.compile(
    r"\b(?:does not establish|is not|not)\b.{0,100}"
    r"\b(?:interoperability|standard|certification)\b",
    re.IGNORECASE,
)

EXPECTED_PNG_DIMENSIONS = {
    "assets/social-card.png": (1280, 640),
    "assets/apple-touch-icon.png": (180, 180),
}

PUBLIC_METRICS = (
    (
        ("counts", "conformance", "cases"),
        ("core conformance cases", "conformance cases"),
    ),
    (
        ("counts", "effect_profiles", "total_vectors"),
        ("effect-profile vectors", "effect profile vectors", "profile vectors"),
    ),
    (
        ("counts", "lean", "theorems"),
        ("lean theorem declarations", "lean theorems"),
    ),
    (
        ("tla_observation", "result", "distinct_states"),
        ("distinct bounded tla+ states", "distinct tla+ states", "distinct states"),
    ),
)


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_pairs_no_duplicates,
    )


def _nested(document: Any, path: tuple[str, ...]) -> Any:
    current = document
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise ValueError(f"missing JSON value: {'.'.join(path)}")
        current = current[key]
    return current


def _normalized(text: str) -> str:
    return SPACE.sub(" ", text).strip()


class SiteParser(HTMLParser):
    """Collect metadata, visible text, identifiers, and URL-bearing values."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.document_lang = ""
        self.charsets: list[str] = []
        self.meta: dict[str, list[str]] = {}
        self.links_by_rel: dict[str, list[str]] = {}
        self.references: list[tuple[str, str, bool]] = []
        self.ids: set[str] = set()
        self.duplicate_ids: set[str] = set()
        self.landmarks: dict[str, int] = {
            "header": 0,
            "nav": 0,
            "main": 0,
            "footer": 0,
        }
        self.headings: list[int] = []
        self.images: list[dict[str, str]] = []
        self.local_document_links: list[str] = []
        self.titles: list[str] = []
        self._title_parts: list[str] | None = None
        self._style_parts: list[str] | None = None
        self.styles: list[str] = []
        self.visible_parts: list[str] = []
        self._hidden_depth = 0
        self.has_base = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        lowered = tag.lower()
        if lowered == "html":
            self.document_lang = values.get("lang", "")
        if lowered == "base":
            self.has_base = True
        if lowered == "meta":
            if "charset" in values:
                self.charsets.append(values["charset"])
            key = values.get("name") or values.get("property")
            if key:
                self.meta.setdefault(key.lower(), []).append(values.get("content", ""))
        if lowered == "link":
            href = values.get("href")
            for rel in values.get("rel", "").lower().split():
                if href:
                    self.links_by_rel.setdefault(rel, []).append(href)
        if "id" in values:
            identifier = values["id"]
            if identifier in self.ids:
                self.duplicate_ids.add(identifier)
            self.ids.add(identifier)
        if lowered in self.landmarks:
            self.landmarks[lowered] += 1
        if re.fullmatch(r"h[1-6]", lowered):
            self.headings.append(int(lowered[1]))
        if lowered == "img":
            self.images.append(values)
        if lowered == "a" and "href" in values:
            target = _local_relative(values["href"])
            if target and _is_human_document_target(target):
                self.local_document_links.append(values["href"])
        if lowered == "title":
            self._title_parts = []
        if lowered == "style":
            self._style_parts = []
            self._hidden_depth += 1
        elif lowered in {"script", "template"}:
            self._hidden_depth += 1

        asset_tags = {"img", "script", "source", "video", "audio", "object"}
        link_asset_rels = {
            "apple-touch-icon",
            "icon",
            "manifest",
            "preload",
            "stylesheet",
        }
        link_rels = set(values.get("rel", "").lower().split())
        for attribute in ("href", "src", "poster", "data"):
            value = values.get(attribute)
            if value:
                is_asset = lowered in asset_tags or (
                    lowered == "link" and bool(link_rels & link_asset_rels)
                )
                self.references.append((f"<{lowered}> {attribute}", value, is_asset))
        if "srcset" in values:
            for candidate in _srcset_urls(values["srcset"]):
                self.references.append((f"<{lowered}> srcset", candidate, True))
        if "style" in values:
            for url in _css_urls(values["style"]):
                self.references.append((f"<{lowered}> style", url, True))

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered == "title" and self._title_parts is not None:
            self.titles.append(_normalized("".join(self._title_parts)))
            self._title_parts = None
        if lowered == "style" and self._style_parts is not None:
            self.styles.append("".join(self._style_parts))
            self._style_parts = None
            self._hidden_depth = max(0, self._hidden_depth - 1)
        elif lowered in {"script", "template"}:
            self._hidden_depth = max(0, self._hidden_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._title_parts is not None:
            self._title_parts.append(data)
        if self._style_parts is not None:
            self._style_parts.append(data)
        if self._hidden_depth == 0 and self._title_parts is None:
            self.visible_parts.append(data)


def _srcset_urls(value: str) -> list[str]:
    urls: list[str] = []
    for candidate in value.split(","):
        parts = candidate.strip().split()
        if parts:
            urls.append(parts[0])
    return urls


def _css_urls(value: str) -> list[str]:
    return [match.group(2).strip() for match in CSS_URL.finditer(value)]


def _parse_html(path: Path) -> SiteParser:
    parser = SiteParser()
    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()
    for style in parser.styles:
        for url in _css_urls(style):
            parser.references.append(("<style> url", url, True))
    return parser


def _only(mapping: dict[str, list[str]], key: str, findings: list[str]) -> str:
    values = mapping.get(key, [])
    if len(values) != 1 or not values[0].strip():
        findings.append(f"metadata {key!r} must occur exactly once with content")
        return ""
    return values[0].strip()


def _check_metadata(parser: SiteParser, findings: list[str]) -> dict[str, str]:
    if parser.document_lang.lower() != "en":
        findings.append("<html> must declare lang=\"en\"")
    if [value.lower() for value in parser.charsets] != ["utf-8"]:
        findings.append("the document must declare one UTF-8 charset")
    if parser.has_base:
        findings.append("<base> is not allowed because it changes local URL resolution")
    if len(parser.titles) != 1 or not parser.titles[0]:
        findings.append("the document must contain one non-empty <title>")
        title = ""
    else:
        title = parser.titles[0]
        if len(title) > 70:
            findings.append("the document title must not exceed 70 characters")

    description = _only(parser.meta, "description", findings)
    viewport = _only(parser.meta, "viewport", findings)
    theme_color = _only(parser.meta, "theme-color", findings)
    if theme_color and not re.fullmatch(r"#[0-9a-fA-F]{6}", theme_color):
        findings.append("theme-color must use six-digit hexadecimal notation")
    if description and not 30 <= len(description) <= 200:
        findings.append("the description must contain 30 to 200 characters")
    if viewport:
        compact_viewport = viewport.lower().replace(" ", "")
        if "width=device-width" not in compact_viewport or "initial-scale=1" not in compact_viewport:
            findings.append("viewport must include width=device-width and initial-scale=1")

    canonicals = parser.links_by_rel.get("canonical", [])
    if canonicals != [PUBLIC_BASE]:
        findings.append(f"canonical URL must occur once and equal {PUBLIC_BASE}")
    canonical = canonicals[0] if len(canonicals) == 1 else ""

    required = {
        "og:type": "website",
        "og:url": canonical,
        "og:image:type": "image/png",
        "og:image:width": "1280",
        "og:image:height": "640",
        "twitter:card": "summary_large_image",
    }
    observed: dict[str, str] = {}
    for key, expected in required.items():
        value = _only(parser.meta, key, findings)
        observed[key] = value
        if value and expected and value != expected:
            findings.append(f"metadata {key!r} must equal {expected!r}")

    for key in (
        "og:title",
        "og:description",
        "og:image",
        "og:image:alt",
        "twitter:title",
        "twitter:description",
        "twitter:image",
        "twitter:image:alt",
    ):
        observed[key] = _only(parser.meta, key, findings)
    if observed["og:title"] and observed["twitter:title"]:
        if observed["og:title"] != observed["twitter:title"]:
            findings.append("Open Graph and Twitter titles must match")
        if len(observed["og:title"]) > 70:
            findings.append("social metadata title must not exceed 70 characters")
    if title and observed["og:title"] and not title.startswith(observed["og:title"]):
        findings.append("the document title must begin with the social metadata title")
    if observed["og:description"] and observed["twitter:description"]:
        if observed["og:description"] != observed["twitter:description"]:
            findings.append("Open Graph and Twitter descriptions must match")
        if not 30 <= len(observed["og:description"]) <= 200:
            findings.append("social metadata description must contain 30 to 200 characters")
    if observed["og:image"] and observed["twitter:image"]:
        if observed["og:image"] != observed["twitter:image"]:
            findings.append("Open Graph and Twitter image URLs must match")
    if observed["og:image:alt"] and observed["twitter:image:alt"]:
        if observed["og:image:alt"] != observed["twitter:image:alt"]:
            findings.append("Open Graph and Twitter image alt text must match")
    if observed["og:image"] and not observed["og:image"].startswith(PUBLIC_BASE):
        findings.append("the social image URL must be an absolute URL under the public site")

    icons = parser.links_by_rel.get("icon", [])
    touch_icons = parser.links_by_rel.get("apple-touch-icon", [])
    if len(icons) != 1:
        findings.append("one favicon link is required")
    if len(touch_icons) != 1:
        findings.append("one apple-touch-icon link is required")
    observed["canonical"] = canonical
    return observed


def _is_root_relative(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("/")


def _local_relative(value: str) -> str | None:
    stripped = value.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parsed = urlsplit(stripped)
    if parsed.scheme or parsed.netloc:
        if stripped.startswith(PUBLIC_BASE):
            return unquote(stripped[len(PUBLIC_BASE):].split("?", 1)[0].split("#", 1)[0])
        return None
    return unquote(parsed.path)


def _is_human_document_target(relative: str) -> bool:
    """Return true for repository documents that the public site must open on GitHub."""
    name = Path(relative).name.lower()
    return Path(name).suffix in {".md", ".lean"} or name == "license" or name.startswith("license.")


def _check_structure(parser: SiteParser, findings: list[str]) -> None:
    if parser.duplicate_ids:
        findings.append("duplicate HTML ids: " + ", ".join(sorted(parser.duplicate_ids)))
    if parser.headings.count(1) != 1:
        findings.append("the document must contain exactly one <h1>")
    for previous, current in zip(parser.headings, parser.headings[1:]):
        if current > previous + 1:
            findings.append(f"heading hierarchy skips from h{previous} to h{current}")
    for landmark, count in parser.landmarks.items():
        if count == 0:
            findings.append(f"the document must contain a <{landmark}> landmark")
    for index, attributes in enumerate(parser.images, start=1):
        if "alt" not in attributes:
            findings.append(f"image {index} must declare alt text (empty is valid for decorative images)")
        for dimension in ("width", "height"):
            value = attributes.get(dimension, "")
            if not value.isdecimal() or int(value) <= 0:
                findings.append(f"image {index} must declare a positive integer {dimension}")
    for target in parser.local_document_links:
        findings.append(
            "human-readable document links must use their GitHub URL, not a local file: "
            + target
        )


def _resolved_local(root: Path, source: Path, relative: str) -> Path:
    if not relative or relative.endswith("/"):
        candidate = source.parent if not relative else source.parent / relative
    else:
        candidate = source.parent / relative
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"local path escapes the repository: {relative}") from error
    return resolved


def _check_reference(
    root: Path,
    source: Path,
    context: str,
    value: str,
    asset: bool,
    findings: list[str],
    ids: set[str] | None = None,
) -> None:
    stripped = value.strip()
    if _is_root_relative(stripped):
        findings.append(f"{source.relative_to(root).as_posix()}: root-relative URL in {context}: {stripped}")
        return
    parsed = urlsplit(stripped)
    if parsed.scheme.lower() == "javascript":
        findings.append(f"{source.relative_to(root).as_posix()}: javascript URL in {context}")
        return
    if stripped.startswith("#"):
        fragment = unquote(stripped[1:])
        if ids is not None and fragment not in ids:
            findings.append(f"{source.relative_to(root).as_posix()}: missing fragment target: #{fragment}")
        return
    relative = _local_relative(stripped)
    if relative is None:
        return
    try:
        target = _resolved_local(root, source, relative)
    except ValueError as error:
        findings.append(f"{source.relative_to(root).as_posix()}: {error}")
        return
    if not target.exists():
        findings.append(
            f"{source.relative_to(root).as_posix()}: missing local target in {context}: {relative}"
        )
    elif asset and not target.is_file():
        findings.append(
            f"{source.relative_to(root).as_posix()}: asset target is not a file in {context}: {relative}"
        )


def _check_html_references(root: Path, path: Path, parser: SiteParser, findings: list[str]) -> None:
    for context, value, asset in parser.references:
        _check_reference(root, path, context, value, asset, findings, parser.ids)


def _check_svg_references(root: Path, findings: list[str]) -> None:
    assets = root / "assets"
    if not assets.is_dir():
        findings.append("missing assets directory")
        return
    for path in sorted(assets.rglob("*.svg")):
        try:
            tree = ET.parse(path)
        except ET.ParseError as error:
            findings.append(f"{path.relative_to(root).as_posix()}: invalid SVG XML: {error}")
            continue
        for element in tree.iter():
            for key, value in element.attrib.items():
                local_key = key.rsplit("}", 1)[-1].lower()
                if local_key in {"href", "src"}:
                    _check_reference(root, path, local_key, value, True, findings)
                elif local_key == "style":
                    for url in _css_urls(value):
                        _check_reference(root, path, "style", url, True, findings)
            if element.tag.rsplit("}", 1)[-1].lower() == "style" and element.text:
                for url in _css_urls(element.text):
                    _check_reference(root, path, "<style> url", url, True, findings)


def _read_png_dimensions(path: Path) -> tuple[int, int]:
    header = path.read_bytes()[:33]
    if len(header) != 33 or header[:8] != PNG_SIGNATURE:
        raise ValueError("invalid PNG signature or truncated IHDR")
    length = struct.unpack(">I", header[8:12])[0]
    if length != 13 or header[12:16] != b"IHDR":
        raise ValueError("PNG must begin with a 13-byte IHDR chunk")
    expected_crc = struct.unpack(">I", header[29:33])[0]
    observed_crc = binascii.crc32(header[12:29]) & 0xFFFFFFFF
    if expected_crc != observed_crc:
        raise ValueError("invalid PNG IHDR checksum")
    width, height = struct.unpack(">II", header[16:24])
    if width == 0 or height == 0:
        raise ValueError("PNG dimensions must be nonzero")
    return width, height


def _check_pngs(root: Path, metadata: dict[str, str], findings: list[str]) -> None:
    observed_dimensions: dict[str, tuple[int, int]] = {}
    for relative, expected in EXPECTED_PNG_DIMENSIONS.items():
        path = root / relative
        if not path.is_file():
            findings.append(f"missing required PNG: {relative}")
            continue
        try:
            observed = _read_png_dimensions(path)
        except (OSError, ValueError) as error:
            findings.append(f"{relative}: {error}")
            continue
        observed_dimensions[relative] = observed
        if observed != expected:
            findings.append(f"{relative}: expected dimensions {expected}, observed {observed}")

    social_url = metadata.get("og:image", "")
    social_relative = _local_relative(social_url)
    if social_relative != "assets/social-card.png":
        findings.append("og:image must identify assets/social-card.png")
    elif social_relative in observed_dimensions:
        width, height = observed_dimensions[social_relative]
        if metadata.get("og:image:width") != str(width):
            findings.append("og:image:width does not match the PNG width")
        if metadata.get("og:image:height") != str(height):
            findings.append("og:image:height does not match the PNG height")


def _numbers(value: int) -> tuple[str, ...]:
    return str(value), f"{value:,}"


def _metric_is_visible(text: str, labels: tuple[str, ...], value: int) -> bool:
    lowered = text.lower()
    for label in labels:
        escaped_label = re.escape(label)
        for number in _numbers(value):
            escaped_number = re.escape(number)
            patterns = (
                rf"\b{escaped_number}\b.{{0,80}}{escaped_label}",
                rf"{escaped_label}.{{0,80}}\b{escaped_number}\b",
            )
            if any(re.search(pattern, lowered, re.IGNORECASE) for pattern in patterns):
                return True
    return False


def _check_evidence(root: Path, visible_text: str, findings: list[str]) -> None:
    try:
        summary = _load_json(root / "evidence-summary.json")
        tla = _load_json(root / "formal" / "tla" / "result.json")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        findings.append(f"cannot load evidence data: {error}")
        return

    if summary.get("status") != "implementer-draft":
        findings.append("evidence-summary.json status must be implementer-draft")

    comparisons = (
        (("tla_observation", "model"), ("model",)),
        (("tla_observation", "configuration"), ("configuration",)),
        (("tla_observation", "tla2tools_version"), ("inputs", "tla2tools_version")),
        (("tla_observation", "tlc_version"), ("inputs", "tlc_version")),
        (("tla_observation", "tla2tools_sha256"), ("inputs", "tla2tools_sha256")),
        (("tla_observation", "result", "generated_states"), ("result", "generated_states")),
        (("tla_observation", "result", "distinct_states"), ("result", "distinct_states")),
        (("tla_observation", "result", "depth"), ("result", "depth")),
    )
    for summary_path, tla_path in comparisons:
        try:
            summary_value = _nested(summary, summary_path)
            tla_value = _nested(tla, tla_path)
        except ValueError as error:
            findings.append(str(error))
            continue
        if summary_value != tla_value:
            findings.append(
                "TLA evidence mismatch: "
                f"{'.'.join(summary_path)}={summary_value!r} "
                f"but {'.'.join(tla_path)}={tla_value!r}"
            )

    if _nested_or_none(tla, ("result", "status")) != "pass":
        findings.append("formal/tla/result.json must record status pass")
    if _nested_or_none(tla, ("result", "complete_bounded_search")) is not True:
        findings.append("formal/tla/result.json must record a complete bounded search")
    if _nested_or_none(tla, ("result", "states_left_on_queue")) != 0:
        findings.append("formal/tla/result.json must record zero states left on queue")

    for path, labels in PUBLIC_METRICS:
        try:
            value = _nested(summary, path)
        except ValueError as error:
            findings.append(str(error))
            continue
        if not isinstance(value, int) or isinstance(value, bool):
            findings.append(f"public evidence value must be an integer: {'.'.join(path)}")
            continue
        if not _metric_is_visible(visible_text, labels, value):
            findings.append(
                f"site does not show {'.'.join(path)}={value} next to its evidence label"
            )


def _nested_or_none(document: Any, path: tuple[str, ...]) -> Any:
    try:
        return _nested(document, path)
    except ValueError:
        return None


def _check_boundary(visible_text: str, findings: list[str]) -> None:
    text = _normalized(visible_text)
    if not IMPLEMENTER_DRAFT.search(text):
        findings.append("site must visibly identify Core 0.1 as an implementer draft")
    if not DEPLOYMENT_BOUNDARY.search(text):
        findings.append("site must visibly state a deployment or production boundary")
    if not ECOSYSTEM_BOUNDARY.search(text):
        findings.append("site must visibly state a standard, certification, or interoperability boundary")


def check_site(root: Path = ROOT) -> list[str]:
    """Return deterministic findings for one repository root."""
    findings: list[str] = []
    root = root.resolve()
    if not (root / ".nojekyll").is_file():
        findings.append("missing .nojekyll")
    index = root / "index.html"
    if not index.is_file():
        return ["missing index.html"]
    try:
        parser = _parse_html(index)
    except (OSError, UnicodeError) as error:
        return [f"cannot parse index.html: {error}"]

    metadata = _check_metadata(parser, findings)
    _check_structure(parser, findings)
    _check_html_references(root, index, parser, findings)
    _check_svg_references(root, findings)
    _check_pngs(root, metadata, findings)
    visible_text = _normalized(" ".join(parser.visible_parts))
    _check_evidence(root, visible_text, findings)
    _check_boundary(visible_text, findings)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root to validate",
    )
    arguments = parser.parse_args()
    findings = check_site(arguments.root)
    if findings:
        for finding in findings:
            print(f"FAIL site: {finding}", file=sys.stderr)
        return 1
    print(
        "PASS site "
        "metadata=seo,og,twitter "
        "png=1280x640,180x180 "
        "evidence=conformance,profiles,lean,tla"
    )
    print("BOUNDARY Core 0.1 remains an implementer draft")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

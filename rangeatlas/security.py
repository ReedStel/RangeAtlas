"""Scope enforcement, bounded reads, safe XML loading, and report redaction."""

from __future__ import annotations

import ipaddress
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path


DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class EvidenceError(ValueError):
    """Raised when an evidence file is malformed or outside safe limits."""


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    target: str
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    name: str
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    require_private: bool = True
    allow_loopback: bool = False

    @classmethod
    def from_toml(cls, path: str | Path) -> "ScopePolicy":
        raw = tomllib.loads(read_bounded_text(path))
        section = raw.get("scope")
        if not isinstance(section, dict):
            raise EvidenceError("scope policy must contain a [scope] table")

        raw_cidrs = section.get("allow_cidrs", [])
        if not isinstance(raw_cidrs, list) or not raw_cidrs:
            raise EvidenceError("scope.allow_cidrs must contain at least one network")

        try:
            networks = tuple(ipaddress.ip_network(str(cidr), strict=True) for cidr in raw_cidrs)
        except ValueError as exc:
            raise EvidenceError(f"invalid scope CIDR: {exc}") from exc

        return cls(
            name=str(section.get("name", "Authorised lab")),
            networks=networks,
            require_private=bool(section.get("require_private", True)),
            allow_loopback=bool(section.get("allow_loopback", False)),
        )

    def evaluate(self, target: str) -> ScopeDecision:
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            return ScopeDecision(target, False, "literal IP address required; DNS is not resolved")

        if address.is_unspecified or address.is_multicast:
            return ScopeDecision(target, False, "unspecified and multicast addresses are denied")
        if address.is_loopback and not self.allow_loopback:
            return ScopeDecision(target, False, "loopback is not enabled by this policy")
        if self.require_private and not address.is_private:
            return ScopeDecision(target, False, "public addresses are denied by policy")
        if not any(address in network for network in self.networks):
            return ScopeDecision(target, False, "address is outside the authorised CIDR list")
        return ScopeDecision(target, True, f"within {self.name}")

    def require(self, targets: list[str] | tuple[str, ...] | set[str]) -> None:
        denied = [decision for target in targets if not (decision := self.evaluate(target)).allowed]
        if denied:
            summary = "; ".join(f"{item.target}: {item.reason}" for item in denied)
            raise EvidenceError(f"scope validation failed: {summary}")


def read_bounded(path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    candidate = Path(path)
    try:
        size = candidate.stat().st_size
    except OSError as exc:
        raise EvidenceError(f"cannot read {candidate}: {exc}") from exc
    if size > max_bytes:
        raise EvidenceError(f"{candidate} exceeds the {max_bytes}-byte evidence limit")
    try:
        return candidate.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read {candidate}: {exc}") from exc


def read_bounded_text(path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    try:
        return read_bounded(path, max_bytes=max_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{path} is not valid UTF-8") from exc


def parse_xml_bounded(path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> ET.Element:
    """Parse XML while rejecting entity declarations and trimming a harmless internal DTD.

    Burp issue exports may contain an internal DTD. The DTD is not needed for reporting, so it is
    removed before parsing. Entity declarations are rejected outright to avoid expansion and
    external-reference surprises in evidence supplied by another tool.
    """

    text = read_bounded_text(path, max_bytes=max_bytes)
    if re.search(r"<!ENTITY\b", text, flags=re.IGNORECASE):
        raise EvidenceError(f"{path} contains a forbidden XML entity declaration")
    text = _remove_doctype(text)
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise EvidenceError(f"invalid XML in {path}: {exc}") from exc


def _remove_doctype(text: str) -> str:
    match = re.search(r"<!DOCTYPE\b", text, flags=re.IGNORECASE)
    if not match:
        return text

    quote: str | None = None
    bracket_depth = 0
    index = match.start()
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "[":
            bracket_depth += 1
        elif char == "]" and bracket_depth:
            bracket_depth -= 1
        elif char == ">" and bracket_depth == 0:
            return text[: match.start()] + text[index + 1 :]
        index += 1
    raise EvidenceError("unterminated XML document type declaration")


_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s<]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|token|secret)\b\s*[:=]\s*[^\s,;<]+"), r"\1=[REDACTED]"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[REDACTED-EMAIL]"),
    (re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@"), r"\1[REDACTED]@"),
)


def redact_text(value: str) -> str:
    result = value
    for pattern, replacement in _SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return " ".join(result.split())


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"br", "p", "li", "div"}:
            self.parts.append(" ")


def clean_evidence_text(value: str | None) -> str:
    parser = _TextExtractor()
    parser.feed(value or "")
    parser.close()
    return redact_text(" ".join(parser.parts))

"""Burp Suite issue-export XML importer.

Raw HTTP requests and responses are intentionally ignored because they commonly contain secrets.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..security import EvidenceError, clean_evidence_text, parse_xml_bounded


def _text(node, name: str) -> str:
    child = node.find(name)
    return clean_evidence_text("" if child is None else "".join(child.itertext()))


def parse_burp_xml(path: str | Path) -> list[Finding]:
    root = parse_xml_bounded(path)
    if root.tag != "issues":
        raise EvidenceError(f"{path} is not a Burp issue-export XML document")

    findings: list[Finding] = []
    for issue in root.findall("issue"):
        host = issue.find("host")
        target = ""
        if host is not None:
            target = clean_evidence_text(host.get("ip", "") or "".join(host.itertext()))
        findings.append(
            Finding(
                source="Burp Suite",
                title=_text(issue, "name") or "Unnamed web finding",
                severity=(_text(issue, "severity") or "information").lower(),
                target=target,
                confidence=_text(issue, "confidence"),
                path=_text(issue, "path") or _text(issue, "location"),
                detail=_text(issue, "issueDetail") or _text(issue, "issueBackground"),
                remediation=_text(issue, "remediationDetail") or _text(issue, "remediationBackground"),
                reference_id=_text(issue, "serialNumber"),
            )
        )

    return findings


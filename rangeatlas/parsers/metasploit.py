"""Sanitised Metasploit workspace XML importer.

Credentials, loot, task logs, and raw payload material are never imported.
"""

from __future__ import annotations

from pathlib import Path

from ..models import Asset, Finding, Service, ValidationEvent
from ..security import EvidenceError, clean_evidence_text, parse_xml_bounded


def _child_text(node, *names: str) -> str:
    for name in names:
        child = node.find(name)
        if child is not None:
            return clean_evidence_text("".join(child.itertext()))
    return ""


def _integer(value: str) -> int:
    try:
        result = int(value)
    except ValueError:
        return 0
    return result if 1 <= result <= 65535 else 0


def parse_metasploit_xml(
    path: str | Path,
) -> tuple[list[Asset], list[Finding], list[ValidationEvent]]:
    root = parse_xml_bounded(path)
    if not root.tag.lower().startswith("metasploit"):
        raise EvidenceError(f"{path} is not a Metasploit workspace XML document")

    assets: list[Asset] = []
    findings: list[Finding] = []
    validations: list[ValidationEvent] = []

    for host in root.findall("./hosts/host"):
        address = _child_text(host, "address")
        if not address:
            continue
        asset = Asset(
            address=address,
            hostname=_child_text(host, "name"),
            status=_child_text(host, "state"),
            os_name=" ".join(
                part
                for part in (_child_text(host, "os-name"), _child_text(host, "os-flavor"))
                if part
            ),
            sources=["Metasploit"],
        )

        for service in host.findall("./services/service"):
            port = _integer(_child_text(service, "port"))
            if not port:
                continue
            asset.services.append(
                Service(
                    port=port,
                    protocol=_child_text(service, "proto") or "unknown",
                    name=_child_text(service, "name") or "unknown",
                    state=_child_text(service, "state"),
                    product=_child_text(service, "info"),
                    source="Metasploit",
                )
            )

        for vuln in host.findall("./vulns/vuln"):
            findings.append(
                Finding(
                    source="Metasploit",
                    title=_child_text(vuln, "name") or "Workspace validation",
                    severity="validated",
                    target=address,
                    confidence="Confirmed in isolated lab",
                    detail=_child_text(vuln, "info"),
                    remediation="Review the affected service and verify the relevant vendor hardening guidance.",
                    reference_id=_child_text(vuln, "id"),
                )
            )

        for session in host.findall("./sessions/session"):
            validations.append(
                ValidationEvent(
                    source="Metasploit",
                    title=_child_text(session, "via-exploit", "desc") or "Controlled lab validation",
                    target=address,
                    outcome="Session recorded in sanitised workspace export",
                    timestamp=_child_text(session, "opened-at", "created-at"),
                    note="Only session metadata was imported; credentials, loot, and payload data were excluded.",
                )
            )

        asset.services.sort(key=lambda item: (item.port, item.protocol))
        assets.append(asset)

    return assets, findings, validations

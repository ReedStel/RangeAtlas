"""Deterministic evidence correlation across tool-specific importers."""

from __future__ import annotations

import ipaddress

from .models import Asset, EvidenceBundle, Finding, PacketSummary, ProjectMetadata, Service, ValidationEvent


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "validated": 4,
    "information": 5,
    "info": 5,
}


def _service_key(service: Service) -> tuple[int, str, str]:
    return service.port, service.protocol.lower(), service.name.lower()


def merge_assets(groups: list[list[Asset]]) -> list[Asset]:
    merged: dict[str, Asset] = {}
    for assets in groups:
        for candidate in assets:
            current = merged.setdefault(candidate.address, Asset(address=candidate.address))
            current.hostname = current.hostname or candidate.hostname
            current.status = current.status or candidate.status
            current.os_name = current.os_name or candidate.os_name
            current.sources = sorted(set(current.sources + candidate.sources))

            existing = {_service_key(service): service for service in current.services}
            for service in candidate.services:
                key = _service_key(service)
                if key not in existing:
                    current.services.append(service)
                    existing[key] = service
                    continue
                saved = existing[key]
                saved.state = saved.state or service.state
                saved.product = saved.product or service.product
                saved.version = saved.version or service.version
                saved.source = ", ".join(sorted(set(filter(None, [saved.source, service.source]))))
            current.services.sort(key=lambda item: (item.port, item.protocol, item.name))
    return sorted(merged.values(), key=lambda item: ipaddress.ip_address(item.address))


def build_bundle(
    *,
    metadata: ProjectMetadata,
    nmap_assets: list[Asset],
    metasploit_assets: list[Asset],
    burp_findings: list[Finding],
    metasploit_findings: list[Finding],
    traffic: PacketSummary,
    validations: list[ValidationEvent],
    source_files: list[str],
) -> EvidenceBundle:
    findings = burp_findings + metasploit_findings
    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity.lower(), 99),
            item.target,
            item.title.lower(),
            item.source,
        )
    )
    validations.sort(key=lambda item: (item.timestamp, item.target, item.title))
    return EvidenceBundle(
        metadata=metadata,
        assets=merge_assets([nmap_assets, metasploit_assets]),
        findings=findings,
        traffic=traffic,
        validations=validations,
        source_files=sorted(source_files),
    )


def scope_addresses(bundle: EvidenceBundle) -> set[str]:
    """Return literal IP addresses referenced by the correlated evidence."""

    candidates = {asset.address for asset in bundle.assets}
    candidates.update(item.source for item in bundle.traffic.conversations)
    candidates.update(item.destination for item in bundle.traffic.conversations)
    for finding in bundle.findings:
        candidates.add(finding.target)

    result: set[str] = set()
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        result.add(candidate)
    return result


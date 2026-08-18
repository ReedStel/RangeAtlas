"""Nmap XML importer."""

from __future__ import annotations

from pathlib import Path

from ..models import Asset, Service
from ..security import EvidenceError, clean_evidence_text, parse_xml_bounded


def parse_nmap_xml(path: str | Path) -> list[Asset]:
    root = parse_xml_bounded(path)
    if root.tag != "nmaprun":
        raise EvidenceError(f"{path} is not an Nmap XML document")

    assets: list[Asset] = []
    for host in root.findall("host"):
        status = host.find("status")
        address_node = next(
            (node for node in host.findall("address") if node.get("addrtype") in {"ipv4", "ipv6"}),
            None,
        )
        if address_node is None or not address_node.get("addr"):
            continue

        hostname_node = host.find("./hostnames/hostname")
        os_match = host.find("./os/osmatch")
        asset = Asset(
            address=address_node.get("addr", ""),
            hostname=clean_evidence_text(hostname_node.get("name", "")) if hostname_node is not None else "",
            status=status.get("state", "") if status is not None else "",
            os_name=clean_evidence_text(os_match.get("name", "")) if os_match is not None else "",
            sources=["Nmap"],
        )

        for port in host.findall("./ports/port"):
            state_node = port.find("state")
            service_node = port.find("service")
            try:
                port_number = int(port.get("portid", "0"))
            except ValueError:
                continue
            if not 1 <= port_number <= 65535:
                continue

            asset.services.append(
                Service(
                    port=port_number,
                    protocol=port.get("protocol", "unknown"),
                    name=service_node.get("name", "unknown") if service_node is not None else "unknown",
                    state=state_node.get("state", "") if state_node is not None else "",
                    product=clean_evidence_text(service_node.get("product", "")) if service_node is not None else "",
                    version=clean_evidence_text(service_node.get("version", "")) if service_node is not None else "",
                    source="Nmap",
                )
            )

        asset.services.sort(key=lambda item: (item.port, item.protocol))
        assets.append(asset)

    return sorted(assets, key=lambda item: item.address)


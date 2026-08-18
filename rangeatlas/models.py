"""Small, serialisable domain models shared by the importers and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Service:
    port: int
    protocol: str
    name: str
    state: str = ""
    product: str = ""
    version: str = ""
    source: str = ""


@dataclass(slots=True)
class Asset:
    address: str
    hostname: str = ""
    status: str = ""
    os_name: str = ""
    services: list[Service] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Finding:
    source: str
    title: str
    severity: str
    target: str
    confidence: str = ""
    path: str = ""
    detail: str = ""
    remediation: str = ""
    reference_id: str = ""


@dataclass(slots=True)
class Conversation:
    source: str
    destination: str
    protocol: str
    packets: int
    first_seen: str = ""
    last_seen: str = ""


@dataclass(slots=True)
class PacketSummary:
    packets: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    conversations: list[Conversation] = field(default_factory=list)


@dataclass(slots=True)
class ValidationEvent:
    source: str
    title: str
    target: str
    outcome: str
    timestamp: str = ""
    note: str = ""


@dataclass(slots=True)
class ProjectMetadata:
    name: str
    lab_id: str
    analyst: str
    classification: str
    completed_at: str


@dataclass(slots=True)
class EvidenceBundle:
    metadata: ProjectMetadata
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    traffic: PacketSummary = field(default_factory=PacketSummary)
    validations: list[ValidationEvent] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


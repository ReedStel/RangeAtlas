"""TShark JSON importer for offline packet summaries."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from ..models import Conversation, PacketSummary
from ..security import EvidenceError, read_bounded_text


def _lookup(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for nested in value.values():
            found = _lookup(nested, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _lookup(nested, key)
            if found is not None:
                return found
    return None


def _first(value: Any) -> str:
    if isinstance(value, list):
        return _first(value[0]) if value else ""
    return "" if value is None else str(value)


def _protocol(layers: dict[str, Any]) -> str:
    displayed = _first(_lookup(layers, "_ws.col.Protocol"))
    if displayed:
        return displayed.upper()
    chain = _first(_lookup(layers, "frame.protocols"))
    if chain:
        ignored = {"eth", "ethertype", "sll", "ip", "ipv6", "tcp", "udp"}
        names = [part for part in chain.split(":") if part]
        meaningful = [part for part in names if part.lower() not in ignored]
        return (meaningful[-1] if meaningful else names[-1]).upper()
    return "UNKNOWN"


def parse_tshark_json(path: str | Path) -> PacketSummary:
    try:
        payload = json.loads(read_bounded_text(path))
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid TShark JSON in {path}: {exc}") from exc
    if not isinstance(payload, list):
        raise EvidenceError(f"{path} must contain a TShark JSON packet array")

    protocols: Counter[str] = Counter()
    conversations: dict[tuple[str, str, str], dict[str, Any]] = {}

    for packet in payload:
        if not isinstance(packet, dict):
            continue
        layers = packet.get("_source", {}).get("layers", {})
        if not isinstance(layers, dict):
            continue

        source = _first(_lookup(layers, "ip.src")) or _first(_lookup(layers, "ipv6.src"))
        destination = _first(_lookup(layers, "ip.dst")) or _first(_lookup(layers, "ipv6.dst"))
        protocol = _protocol(layers)
        timestamp = _first(_lookup(layers, "frame.time_epoch"))
        protocols[protocol] += 1

        if source and destination:
            key = (source, destination, protocol)
            current = conversations.setdefault(
                key,
                {"packets": 0, "first_seen": timestamp, "last_seen": timestamp},
            )
            current["packets"] += 1
            if timestamp:
                current["first_seen"] = min(current["first_seen"] or timestamp, timestamp)
                current["last_seen"] = max(current["last_seen"] or timestamp, timestamp)

    rows = [
        Conversation(
            source=key[0],
            destination=key[1],
            protocol=key[2],
            packets=value["packets"],
            first_seen=value["first_seen"],
            last_seen=value["last_seen"],
        )
        for key, value in conversations.items()
    ]
    rows.sort(key=lambda item: (-item.packets, item.source, item.destination, item.protocol))
    return PacketSummary(
        packets=len(payload),
        protocols=dict(sorted(protocols.items())),
        conversations=rows,
    )


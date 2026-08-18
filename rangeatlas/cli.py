"""RangeAtlas command-line interface."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

from . import __version__
from .correlation import build_bundle, scope_addresses
from .models import PacketSummary, ProjectMetadata
from .parsers import parse_burp_xml, parse_metasploit_xml, parse_nmap_xml, parse_tshark_json
from .report import write_reports
from .security import EvidenceError, ScopePolicy, read_bounded_text


def _path(base: Path, value: str) -> Path:
    return (base / value).resolve()


def build_from_manifest(manifest_path: Path, output_directory: Path) -> int:
    raw = tomllib.loads(read_bounded_text(manifest_path))
    project = raw.get("project", {})
    evidence = raw.get("evidence", {})
    scope = raw.get("scope", {})
    if not isinstance(project, dict) or not isinstance(evidence, dict) or not isinstance(scope, dict):
        raise EvidenceError("manifest requires [project], [scope], and [evidence] tables")

    required = ("name", "lab_id", "analyst", "classification", "completed_at")
    missing = [name for name in required if not str(project.get(name, "")).strip()]
    if missing:
        raise EvidenceError("manifest is missing project fields: " + ", ".join(missing))

    base = manifest_path.parent
    policy_value = str(scope.get("policy", "")).strip()
    if not policy_value:
        raise EvidenceError("manifest scope.policy is required")
    policy = ScopePolicy.from_toml(_path(base, policy_value))
    declared_targets = scope.get("authorised_targets", [])
    if not isinstance(declared_targets, list) or not declared_targets:
        raise EvidenceError("manifest scope.authorised_targets must be a non-empty list")
    policy.require([str(target) for target in declared_targets])

    source_files: list[str] = []

    def evidence_path(key: str) -> Path | None:
        value = str(evidence.get(key, "")).strip()
        if not value:
            return None
        result = _path(base, value)
        source_files.append(result.name)
        return result

    nmap_path = evidence_path("nmap_xml")
    tshark_path = evidence_path("tshark_json")
    burp_path = evidence_path("burp_xml")
    metasploit_path = evidence_path("metasploit_xml")

    nmap_assets = parse_nmap_xml(nmap_path) if nmap_path else []
    traffic = parse_tshark_json(tshark_path) if tshark_path else PacketSummary()
    burp_findings = parse_burp_xml(burp_path) if burp_path else []
    if metasploit_path:
        metasploit_assets, metasploit_findings, validations = parse_metasploit_xml(metasploit_path)
    else:
        metasploit_assets, metasploit_findings, validations = [], [], []

    bundle = build_bundle(
        metadata=ProjectMetadata(**{name: str(project[name]) for name in required}),
        nmap_assets=nmap_assets,
        metasploit_assets=metasploit_assets,
        burp_findings=burp_findings,
        metasploit_findings=metasploit_findings,
        traffic=traffic,
        validations=validations,
        source_files=source_files,
    )
    policy.require(scope_addresses(bundle))
    paths = write_reports(bundle, output_directory)
    print(
        f"Built {len(paths)} reports from {len(bundle.assets)} assets, "
        f"{len(bundle.findings)} findings, and {bundle.traffic.packets} packets."
    )
    for path in paths:
        print(path)
    return 0


def _scope_command(policy_path: Path, targets: list[str]) -> int:
    policy = ScopePolicy.from_toml(policy_path)
    denied = False
    for target in targets:
        decision = policy.evaluate(target)
        marker = "ALLOW" if decision.allowed else "DENY"
        print(f"{marker:<5} {target:<39} {decision.reason}")
        denied = denied or not decision.allowed
    return 2 if denied else 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="rangeatlas",
        description="Correlate sanitised evidence from an authorised cyber range.",
    )
    root.add_argument("--version", action="version", version=f"RangeAtlas {__version__}")
    commands = root.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="build JSON, Markdown, and HTML reports")
    build.add_argument("--manifest", type=Path, required=True)
    build.add_argument("--out", type=Path, required=True)

    scope = commands.add_parser("scope", help="evaluate literal IPs against an authorised policy")
    scope.add_argument("--policy", type=Path, required=True)
    scope.add_argument("targets", nargs="+")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "build":
            return build_from_manifest(args.manifest.resolve(), args.out.resolve())
        if args.command == "scope":
            return _scope_command(args.policy.resolve(), args.targets)
    except EvidenceError as exc:
        print(f"rangeatlas: {exc}", file=sys.stderr)
        return 2
    return 1

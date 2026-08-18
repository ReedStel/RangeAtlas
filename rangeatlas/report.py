"""Deterministic JSON, Markdown, and self-contained HTML reporting."""

from __future__ import annotations

import json
from collections import Counter
from html import escape
from pathlib import Path

from .models import EvidenceBundle


def _severity_counts(bundle: EvidenceBundle) -> Counter[str]:
    return Counter(item.severity.lower() for item in bundle.findings)


def _services(bundle: EvidenceBundle) -> int:
    return sum(len(asset.services) for asset in bundle.assets)


def render_json(bundle: EvidenceBundle) -> str:
    return json.dumps(bundle.to_dict(), indent=2, sort_keys=True) + "\n"


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ") or "—"


def render_markdown(bundle: EvidenceBundle) -> str:
    meta = bundle.metadata
    severity = _severity_counts(bundle)
    lines = [
        f"# {meta.name}",
        "",
        "> Authorised lab evidence only. RangeAtlas is an offline reporting tool and does not",
        "> launch scanners, proxies, packet capture, or exploitation frameworks.",
        "",
        "## Executive summary",
        "",
        "| Lab ID | Analyst | Classification | Completed |",
        "| --- | --- | --- | --- |",
        f"| {_md(meta.lab_id)} | {_md(meta.analyst)} | {_md(meta.classification)} | {_md(meta.completed_at)} |",
        "",
        "| Assets | Services | Findings | Packets | Validations |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {len(bundle.assets)} | {_services(bundle)} | {len(bundle.findings)} | {bundle.traffic.packets} | {len(bundle.validations)} |",
        "",
        "Finding mix: "
        + (", ".join(f"**{name.title()}** {count}" for name, count in sorted(severity.items())) or "none"),
        "",
        "## Assets and exposed services",
        "",
        "| Address | Hostname | Status | OS | Services | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for asset in bundle.assets:
        service_text = ", ".join(
            f"{service.port}/{service.protocol} {service.name}"
            + (f" ({service.product} {service.version})".rstrip() if service.product or service.version else "")
            for service in asset.services
        )
        lines.append(
            f"| {_md(asset.address)} | {_md(asset.hostname)} | {_md(asset.status)} | "
            f"{_md(asset.os_name)} | {_md(service_text)} | {_md(', '.join(asset.sources))} |"
        )

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Severity | Source | Target | Finding | Confidence |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for finding in bundle.findings:
        target = finding.target + (finding.path if finding.path else "")
        lines.append(
            f"| {_md(finding.severity.title())} | {_md(finding.source)} | {_md(target)} | "
            f"{_md(finding.title)} | {_md(finding.confidence)} |"
        )
        if finding.detail:
            lines.extend(["", f"**{_md(finding.title)} — evidence:** {_md(finding.detail)}"])
        if finding.remediation:
            lines.extend(["", f"**Recommended action:** {_md(finding.remediation)}"])

    lines.extend(["", "## Traffic summary", ""])
    if bundle.traffic.protocols:
        lines.append(
            "Protocols: " + ", ".join(f"**{name}** {count}" for name, count in bundle.traffic.protocols.items())
        )
    else:
        lines.append("No packet evidence was imported.")
    lines.extend(
        [
            "",
            "| Source | Destination | Protocol | Packets | First seen | Last seen |",
            "| --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for conversation in bundle.traffic.conversations:
        lines.append(
            f"| {_md(conversation.source)} | {_md(conversation.destination)} | "
            f"{_md(conversation.protocol)} | {conversation.packets} | "
            f"{_md(conversation.first_seen)} | {_md(conversation.last_seen)} |"
        )

    lines.extend(["", "## Controlled validation timeline", ""])
    if bundle.validations:
        for event in bundle.validations:
            lines.append(
                f"- **{_md(event.timestamp)} — {_md(event.title)}:** {_md(event.outcome)} "
                f"on `{_md(event.target)}`. {_md(event.note)}"
            )
    else:
        lines.append("No validation-session metadata was imported.")

    lines.extend(
        [
            "",
            "## Evidence handling",
            "",
            "- Raw HTTP messages, credentials, loot, payloads, and task logs are deliberately excluded.",
            "- Checked-in examples are synthetic and use a fictional isolated private subnet.",
            "- Review any report built from real lab evidence before sharing it.",
            "- Findings indicate lab observations, not proof of exposure on any external system.",
            "",
            "## Imported files",
            "",
        ]
    )
    lines.extend(f"- `{_md(name)}`" for name in bundle.source_files)
    return "\n".join(lines) + "\n"


def _finding_card(finding) -> str:
    severity_class = escape(finding.severity.lower())
    detail = f"<p>{escape(finding.detail)}</p>" if finding.detail else ""
    remediation = (
        f'<div class="remediation"><strong>Action</strong>{escape(finding.remediation)}</div>'
        if finding.remediation
        else ""
    )
    location = escape(finding.target + (finding.path if finding.path else ""))
    return f"""
    <article class="finding">
      <div class="finding-top"><span class="pill {severity_class}">{escape(finding.severity)}</span>
      <span class="source">{escape(finding.source)}</span></div>
      <h3>{escape(finding.title)}</h3><code>{location}</code>{detail}{remediation}
    </article>"""


def render_html(bundle: EvidenceBundle) -> str:
    meta = bundle.metadata
    service_count = _services(bundle)
    asset_rows = "".join(
        f"<tr><td><code>{escape(asset.address)}</code></td><td>{escape(asset.hostname or '—')}</td>"
        f"<td>{escape(asset.os_name or '—')}</td><td>{escape(', '.join(f'{s.port}/{s.protocol} {s.name}' for s in asset.services) or '—')}</td>"
        f"<td>{escape(', '.join(asset.sources))}</td></tr>"
        for asset in bundle.assets
    )
    finding_cards = "".join(_finding_card(finding) for finding in bundle.findings) or '<p class="empty">No findings imported.</p>'
    protocol_rows = "".join(
        f'<div class="protocol"><span>{escape(name)}</span><strong>{count}</strong></div>'
        for name, count in bundle.traffic.protocols.items()
    ) or '<p class="empty">No packet evidence imported.</p>'
    timeline = "".join(
        f'<li><time>{escape(event.timestamp or "Undated")}</time><div><strong>{escape(event.title)}</strong>'
        f'<p>{escape(event.outcome)} on <code>{escape(event.target)}</code>. {escape(event.note)}</p></div></li>'
        for event in bundle.validations
    ) or '<li class="empty">No validation-session metadata imported.</li>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(meta.name)} · RangeAtlas</title>
  <style>
    :root {{ color-scheme: dark; --bg:#071015; --panel:#0d1b22; --line:#1f3a45; --text:#e8f3f6;
      --muted:#8da6af; --cyan:#43d9d0; --lime:#b4f34d; --orange:#ffac5e; --red:#ff647c; }}
    * {{ box-sizing:border-box }} body {{ margin:0; background:radial-gradient(circle at 15% 0,#11323c 0,transparent 30%),
      var(--bg); color:var(--text); font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif }}
    main {{ width:min(1120px,calc(100% - 32px)); margin:auto; padding:54px 0 80px }}
    header {{ display:grid; grid-template-columns:1fr auto; gap:24px; align-items:end; margin-bottom:30px }}
    .eyebrow {{ color:var(--cyan); text-transform:uppercase; letter-spacing:.18em; font-size:12px; font-weight:800 }}
    h1 {{ margin:.25rem 0 0; font-size:clamp(42px,8vw,82px); line-height:.95; letter-spacing:-.055em }}
    header p {{ max-width:630px; color:var(--muted); font-size:17px }}
    .classification {{ border:1px solid var(--line); border-radius:999px; padding:8px 13px; color:var(--lime); white-space:nowrap }}
    .notice {{ border:1px solid #285565; background:#0a222b; border-radius:14px; padding:14px 17px; color:#b8d6df }}
    .metrics {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin:22px 0 }}
    .metric,.panel,.finding {{ background:linear-gradient(145deg,rgba(17,38,47,.96),rgba(10,24,31,.96));
      border:1px solid var(--line); border-radius:16px }}
    .metric {{ padding:19px }} .metric strong {{ display:block; font-size:31px; letter-spacing:-.04em }}
    .metric span,.source,.empty {{ color:var(--muted) }} section {{ margin-top:34px }}
    h2 {{ font-size:23px; letter-spacing:-.02em }} .panel {{ overflow:auto }} table {{ width:100%; border-collapse:collapse }}
    th,td {{ text-align:left; padding:14px 16px; border-bottom:1px solid var(--line); white-space:nowrap }}
    th {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em }} tr:last-child td {{ border:0 }}
    code {{ color:#9ee9e4; background:#07151b; border:1px solid #17313b; border-radius:6px; padding:2px 6px }}
    .findings {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px }} .finding {{ padding:18px }}
    .finding h3 {{ margin:12px 0 8px }} .finding p {{ color:#bed0d6 }} .finding-top {{ display:flex; justify-content:space-between }}
    .pill {{ border-radius:999px; padding:4px 9px; font-size:11px; font-weight:900; text-transform:uppercase; letter-spacing:.08em }}
    .high,.critical {{ background:#481c28; color:#ff9bad }} .medium {{ background:#49301d; color:#ffc27c }}
    .low,.information,.info {{ background:#123942; color:#77e4dc }} .validated {{ background:#284020; color:#c5f67d }}
    .remediation {{ border-left:3px solid var(--lime); margin-top:14px; padding:8px 12px; color:#cddade }}
    .remediation strong {{ display:block; color:var(--lime); font-size:11px; text-transform:uppercase; letter-spacing:.1em }}
    .traffic {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px }} .protocol {{ background:#0b2028; border:1px solid var(--line); border-radius:12px; padding:14px; display:flex; justify-content:space-between }}
    .protocol span {{ color:var(--muted) }} .protocol strong {{ color:var(--cyan) }}
    .timeline {{ list-style:none; padding:0 }} .timeline li {{ display:grid; grid-template-columns:180px 1fr; gap:20px; padding:17px 0; border-bottom:1px solid var(--line) }}
    .timeline time {{ color:var(--cyan); font-variant-numeric:tabular-nums }} .timeline p {{ margin:5px 0; color:var(--muted) }}
    footer {{ margin-top:54px; color:var(--muted); border-top:1px solid var(--line); padding-top:22px }}
    @media(max-width:760px) {{ header {{ grid-template-columns:1fr }} .metrics {{ grid-template-columns:repeat(2,1fr) }}
      .findings {{ grid-template-columns:1fr }} .traffic {{ grid-template-columns:repeat(2,1fr) }} .timeline li {{ grid-template-columns:1fr;gap:5px }} }}
  </style>
</head>
<body><main>
  <header><div><div class="eyebrow">RangeAtlas / Evidence report</div><h1>{escape(meta.name)}</h1>
    <p>Correlated evidence from an isolated, authorised cyber range. Generated offline from sanitised tool exports.</p></div>
    <div class="classification">{escape(meta.classification)}</div></header>
  <div class="notice"><strong>Safety boundary:</strong> report generation is offline. No scanner, proxy, capture, or exploitation tool was launched.</div>
  <div class="metrics">
    <div class="metric"><strong>{len(bundle.assets)}</strong><span>assets</span></div>
    <div class="metric"><strong>{service_count}</strong><span>services</span></div>
    <div class="metric"><strong>{len(bundle.findings)}</strong><span>findings</span></div>
    <div class="metric"><strong>{bundle.traffic.packets}</strong><span>packets</span></div>
    <div class="metric"><strong>{len(bundle.validations)}</strong><span>validations</span></div>
  </div>
  <section><h2>Asset surface</h2><div class="panel"><table><thead><tr><th>Address</th><th>Hostname</th><th>OS</th><th>Services</th><th>Evidence</th></tr></thead><tbody>{asset_rows}</tbody></table></div></section>
  <section><h2>Correlated findings</h2><div class="findings">{finding_cards}</div></section>
  <section><h2>Observed protocols</h2><div class="traffic">{protocol_rows}</div></section>
  <section><h2>Controlled validation</h2><ol class="timeline">{timeline}</ol></section>
  <footer>Lab {escape(meta.lab_id)} · Analyst {escape(meta.analyst)} · Completed {escape(meta.completed_at)}<br>
    Generated by RangeAtlas 0.1.0 from synthetic or explicitly authorised evidence.</footer>
</main></body></html>\n"""


def write_reports(bundle: EvidenceBundle, output_directory: str | Path) -> tuple[Path, Path, Path]:
    destination = Path(output_directory)
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "report.json"
    markdown_path = destination / "report.md"
    html_path = destination / "report.html"
    json_path.write_text(render_json(bundle), encoding="utf-8")
    markdown_path.write_text(render_markdown(bundle), encoding="utf-8")
    html_path.write_text(render_html(bundle), encoding="utf-8")
    return json_path, markdown_path, html_path

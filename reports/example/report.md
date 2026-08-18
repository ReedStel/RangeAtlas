# RangeAtlas Synthetic Validation

> Authorised lab evidence only. RangeAtlas is an offline reporting tool and does not
> launch scanners, proxies, packet capture, or exploitation frameworks.

## Executive summary

| Lab ID | Analyst | Classification | Completed |
| --- | --- | --- | --- |
| RANGE-DEMO-001 | Reed Stelfox | PUBLIC · SYNTHETIC | 2026-08-19T09:30:00+10:00 |

| Assets | Services | Findings | Packets | Validations |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 4 | 3 | 8 | 1 |

Finding mix: **Information** 1, **Low** 1, **Validated** 1

## Assets and exposed services

| Address | Hostname | Status | OS | Services | Evidence |
| --- | --- | --- | --- | --- | --- |
| 10.77.0.10 | kali.range.test | up | Linux 6.x (synthetic fixture) | 22/tcp ssh (OpenSSH 9.9) | Nmap |
| 10.77.0.20 | range-web.test | up | Ubuntu Linux 22.04 (synthetic fixture) | 22/tcp ssh (OpenSSH 8.9), 8080/tcp http (RangeWeb training service ), 8080/tcp http-proxy (RangeWeb training service 1.0) | Metasploit, Nmap |

## Findings

| Severity | Source | Target | Finding | Confidence |
| --- | --- | --- | --- | --- |
| Low | Burp Suite | 10.77.0.20/ | Content security policy is not configured | Certain |

**Content security policy is not configured — evidence:** The synthetic training response did not include a Content-Security-Policy header.

**Recommended action:** Define a restrictive policy and validate it in report-only mode before enforcement.
| Validated | Metasploit | 10.77.0.20 | Training service validation marker | Confirmed in isolated lab |

**Training service validation marker — evidence:** A deliberately vulnerable fixture path was confirmed inside the isolated range. No external target was involved.

**Recommended action:** Review the affected service and verify the relevant vendor hardening guidance.
| Information | Burp Suite | 10.77.0.20/health | Server version disclosed by response header | Firm |

**Server version disclosed by response header — evidence:** The lab service returned a detailed synthetic Server header.

**Recommended action:** Return a generic server identifier and keep exact component versions in the internal inventory.

## Traffic summary

Protocols: **DNS** 2, **HTTP** 4, **ICMP** 1, **TCP** 1

| Source | Destination | Protocol | Packets | First seen | Last seen |
| --- | --- | --- | ---: | --- | --- |
| 10.77.0.10 | 10.77.0.20 | HTTP | 2 | 1787094002.204 | 1787094004.100 |
| 10.77.0.20 | 10.77.0.10 | HTTP | 2 | 1787094002.288 | 1787094004.204 |
| 10.77.0.10 | 10.77.0.20 | ICMP | 1 | 1787094005.444 | 1787094005.444 |
| 10.77.0.10 | 10.77.0.20 | TCP | 1 | 1787094002.101 | 1787094002.101 |
| 10.77.0.10 | 10.77.0.30 | DNS | 1 | 1787094003.011 | 1787094003.011 |
| 10.77.0.30 | 10.77.0.10 | DNS | 1 | 1787094003.029 | 1787094003.029 |

## Controlled validation timeline

- **2026-08-19T09:18:15+10:00 — exploit/test/range_validation:** Session recorded in sanitised workspace export on `10.77.0.20`. Only session metadata was imported; credentials, loot, and payload data were excluded.

## Evidence handling

- Raw HTTP messages, credentials, loot, payloads, and task logs are deliberately excluded.
- Checked-in examples are synthetic and use a fictional isolated private subnet.
- Review any report built from real lab evidence before sharing it.
- Findings indicate lab observations, not proof of exposure on any external system.

## Imported files

- `burp.xml`
- `metasploit.xml`
- `nmap.xml`
- `tshark.json`

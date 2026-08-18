# Isolated lab guide

This guide defines the intended environment; it does not claim that the author's personal lab has
already been deployed. Follow the current documentation for each product and use only systems you
own or have explicit permission to test.

## Reference topology

| Role | Example address | Purpose |
| --- | --- | --- |
| Kali tooling VM | `10.77.0.10` | Nmap, Burp Suite, Metasploit, and TShark tooling |
| Vulnerable Linux VM | `10.77.0.20` | Deliberately vulnerable training application |
| Analyst Linux VM | `10.77.0.30` | Evidence storage and RangeAtlas execution |

Use a dedicated host-only VMware network for `10.77.0.0/24`. Do not bridge it to an employer,
campus, customer, or household LAN. Disable shared folders and clipboard integration until they are
specifically needed, snapshot clean VM states, and keep vulnerable targets powered off when the lab
is not in use.

## Evidence collection contract

RangeAtlas does not run these commands for you. Examples belong only inside the isolated lab.

### Nmap

Export XML rather than scraping terminal output:

```bash
nmap -sV -oX nmap.xml 10.77.0.20
```

### Wireshark / TShark

Capture only the dedicated virtual interface. Convert a private working capture to JSON outside the
repository:

```bash
tshark -r authorised-lab.pcapng -T json > tshark.json
```

RangeAtlas imports summary fields and does not copy packet bytes into its report.

### Burp Suite

Proxy only the deliberately vulnerable training application. Export selected issue data as XML.
RangeAtlas ignores embedded requests and responses even if the export contains them.

### Metasploit

Create a workspace dedicated to this subnet, perform only the agreed lab validation, then export XML
with `db_export`. Never provide RangeAtlas with PWDump, loot, replay scripts, or a workspace ZIP.

## Remediation demonstration

The best portfolio demo is a controlled before/after comparison:

1. import the baseline exports;
2. record the observed issue and packet pattern;
3. apply a Linux package update, service configuration change, or network ACL;
4. collect fresh authorised evidence;
5. rebuild the report; and
6. explain why the second result demonstrates the control.

Avoid persistence, credential collection, evasion, destructive payloads, and public targets.


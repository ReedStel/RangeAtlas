# Evidence handling

Tool output is often more sensitive than source code. A scan export or capture can reveal enough
about a network to create risk even when it contains no password.

## Never commit

- real `.pcap` or `.pcapng` captures;
- Burp project files, cookies, request bodies, or authentication headers;
- Metasploit loot, credential exports, replay scripts, or workspace ZIP files;
- VPN configurations, private keys, environment files, or API tokens;
- employer, customer, university, or home-network hostnames and addresses;
- Hack The Box flags or active-machine walkthrough material.

The `.gitignore` covers common cases, but it cannot recognise every renamed or copied secret.

## Safe workflow

1. Create a disposable working directory outside the repository.
2. Export the smallest evidence set needed for the report.
3. Remove raw payloads and secrets at the source when the tool offers that option.
4. Run RangeAtlas without administrator or root privileges.
5. Review `report.json`, `report.md`, and `report.html` manually.
6. Publish only deliberately synthetic fixtures or a separately approved sanitised report.
7. Destroy the temporary working directory according to the lab's data-handling plan.

## Built-in controls

- evidence files are bounded to 10 MiB;
- XML entity declarations are refused;
- DNS names are not resolved;
- public and undeclared IPs fail closed;
- request/response bodies, credentials, loot, and payloads are not mapped;
- common secret patterns are redacted from imported descriptive text.

No automated redactor can guarantee that an arbitrary export is safe to publish. Human review is a
required control.


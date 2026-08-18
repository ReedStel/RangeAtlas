# Security policy

## Supported version

Security fixes are made on the latest commit of the `main` branch.

## Reporting a vulnerability

Use GitHub private vulnerability reporting. If that is unavailable, open a public issue asking for
a private reporting channel without including exploit details, credentials, captures, or target
information.

Include the affected commit, the smallest synthetic input that reproduces the behaviour, the
observed result, and the expected safe behaviour.

## Operational boundary

RangeAtlas is an **offline evidence parser**. It does not launch Nmap, Burp Suite, Metasploit,
TShark, or any exploit. Only collect evidence from systems you own or are explicitly authorised to
test.

Treat all real evidence as sensitive. Nmap exports, Burp reports, Metasploit workspaces, and packet
captures can contain internal addresses, cookies, credentials, request bodies, usernames, service
versions, and other identifying information. Keep real evidence outside the repository and review
generated reports before sharing them.

Do not run RangeAtlas with elevated privileges. Parse untrusted evidence in a disposable VM.


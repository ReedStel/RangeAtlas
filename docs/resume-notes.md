# Showcase notes

## One-line explanation

RangeAtlas is an offline Python pipeline that correlates Nmap, Wireshark, Burp Suite, and Metasploit
exports from an authorised cyber range into one deterministic evidence report.

## Resume bullet

Built a safety-gated Python reporting pipeline for authorised cyber ranges, normalising four security
tool formats into deterministic JSON, Markdown, and HTML while excluding credentials, payloads, and
out-of-scope targets.

## Interview walkthrough

1. Explain the problem: lab evidence is fragmented and hard to review.
2. Run the synthetic manifest and open the HTML report.
3. Show the public-IP rejection in the scope command.
4. Point to the parser boundaries that ignore Burp messages and Metasploit secrets.
5. Explain why the project imports evidence instead of orchestrating security tools.
6. Be explicit that checked-in results are synthetic and that no production deployment is claimed.

## Questions worth preparing for

- Why is allowlisting applied both before and after correlation?
- What fields can a packet capture or Burp report expose?
- Why is deterministic output valuable in code review?
- How would report-diffing work without leaking raw evidence?
- What would need to change before this could process untrusted files in production?


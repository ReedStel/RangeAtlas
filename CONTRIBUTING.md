# Contributing

RangeAtlas accepts focused bug reports and proposed contributions that preserve its defensive,
offline-only boundary.

Before opening a pull request:

1. Use only synthetic fixtures that you created and are permitted to publish.
2. Remove credentials, cookies, tokens, public target details, flags, and identifying metadata.
3. Keep network actions out of the core package; import evidence instead of launching tools.
4. Run `python -m unittest discover -s tests -v`.
5. Run `python -m compileall -q rangeatlas`.

Do not attach live packet captures, Burp project files, Metasploit loot, VPN profiles, active
Hack The Box machine solutions, or employer/customer data to issues or pull requests.

The repository is source-available, not open source. See `LICENSE` before preparing a contribution.


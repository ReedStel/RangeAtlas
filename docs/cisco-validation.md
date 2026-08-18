# Cisco validation companion

Cisco belongs in RangeAtlas as a **control-validation source**, not as a logo added to the README.

An optional lab can use Cisco Modeling Labs or a DevNet reservation sandbox to model:

- separate tooling, target, and analyst VLANs;
- an ACL that blocks target-initiated connections to the tooling network;
- management access restricted to the analyst segment;
- logging directed to the analyst VM; and
- an explicit route boundary preventing access to unrelated networks.

Cisco pyATS/Genie can collect read-only operational state before and after a control change. A future
RangeAtlas importer will accept a small, sanitised JSON result containing only pass/fail checks and
fictional device identifiers.

Do not commit a real pyATS testbed file. It may include device addresses, usernames, passwords, and
connection details. Keep `testbed.local.yaml` outside version control and source credentials from
environment variables.

The current release documents this integration but does not claim a deployed Cisco topology or ship
a pyATS runtime dependency.


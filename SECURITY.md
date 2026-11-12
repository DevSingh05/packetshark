# Security

## Reporting a vulnerability

Please report it privately, not in a public issue:
**[Report a vulnerability](https://github.com/DevSingh05/packetshark/security/advisories/new)**
(the Security tab of this repository, then "Report a vulnerability").

Say what you found, how to reproduce it, and which version you used. You
should hear back within a week. Once a fix is released, the report is
published with credit to you unless you ask otherwise.

## Supported versions

Fixes go into the latest release.

## What is in scope

packetshark is routinely pointed at capture files from untrusted sources, so
these matter:

- a capture, or the text inside one, that makes packetshark crash, hang,
  write outside the directory it was asked to, or send escape sequences to
  the terminal;
- anything that makes packetshark run a program other than the Wireshark
  tools it is configured to use.

Packets are dissected by Wireshark's `sharkd`, which runs as a separate
process. A bug in a dissector is a Wireshark bug: please report it to the
[Wireshark project](https://gitlab.com/wireshark/wireshark/-/wikis/ReportingBugs),
and keep Wireshark up to date, since that is where most of the exposure to
hostile captures lies.

# Changelog

Notable changes to packetshark. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

## 0.1.1 - 2026-11-12

### Changed

- Expert information lists each message once, with a count and the first
  packet that carries it, as Wireshark's own dialog does. Enter on a message
  seen many times lists its packets; on one seen once it goes to the packet.

## 0.1.0 - 2026-11-12

The first release.

### Added

- Packet list, protocol details and bytes in three linked panes, with mouse
  support, two layouts and zoom.
- Display filters checked as you type, with field-name completion and history.
- Follow Stream as text, hex dump or raw bytes.
- Statistics: conversations, endpoints, protocol hierarchy, expert
  information, per-protocol trees, and exporting objects.
- Find, go to packet, marks, time references, and copying to the clipboard.
- Live capture through dumpcap, captures piped in on stdin, and files that are
  still being written.
- Columns added from a field while the program runs.
- TLS decryption with a key log file.
- Support for Wireshark 3.6 and newer.
- ASCII drawing for terminals without UTF-8, and `NO_COLOR`.

# Changelog

Notable changes to packetshark. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `:graph` shows packets (or bytes) over time as a bar chart; Enter filters
  the list to the bar under the cursor.
- `:flow` lists who sent what to whom, in order: a call flow.
- `:profile` switches Wireshark configuration profile while running.
- `:decode tcp.port 8080 http`, or `-d` at startup, adds a Decode As rule.
  Your Wireshark configuration is not written to.
- `:sort COLUMN`, or a click on a column's title, sorts the packet list by
  that column; again reverses it, and `:sort off` goes back to capture
  order. Lists of up to 300,000 packets can be sorted.
- `:restart` starts a live capture again, dropping the packets so far.
- `v` in the bytes pane selects a range of bytes, and `y` copies it as hex,
  text, an escaped string, a C array, base64 or a hex dump.

### Fixed

- `:graph` failed on a capture holding packets stamped earlier than its
  first one. The chart now starts before zero for such a capture.
- A profile given with `-C`, or as `profile` in the config file, made sharkd
  exit, so that nothing could be opened. Profiles work now, and one that
  does not exist is reported at startup.

## 0.2.0 - 2026-11-12

### Added

- Colour themes: five built in, your own as small TOML files, chosen with
  `:theme` and remembered.
- A column editor (`:columns`) to reorder, hide, rename, add and delete
  columns, including the Wireshark profile's own.
- Tab completion on the command line, for commands, their arguments and
  file names.
- Marks as in vim: `ma` sets one, `'a` goes to it, `''` goes back. An
  upper-case mark remembers its capture file and is kept between runs.
  `:marks` lists them.
- Find (`s`) searches packet bytes, the details tree or the summary
  columns, as text, a regular expression, hex or a display filter, with or
  without regard to case. The match is highlighted where the search lands,
  and a long search can be stopped with Esc.
- `/` in Follow Stream searches the stream, as text or `/regex/`; `n` and
  `N` step through the matches. The title shows how many packets carried
  the stream and how often it changed sides.
- In the conversation and endpoint tables, `a` and `p` filter on one
  direction only, or combine the row with the filter in use.
- `:info` shows the capture file's properties, and `:recent` lists the
  captures opened lately.
- `-w FILE` keeps the packets of a live or piped capture, and the program
  says on exit where they went. `-t` sets the time format.
- With no terminal on its output, packetshark prints packets through
  tshark: `packetshark x.pcap | less`.
- Ctrl-z suspends to the shell.
- `copy_command` in the config pipes copied text to a program.
- Key mappings: `:map <f5> :conv<enter>` makes a key type a sequence of
  keys, written as in vim, and is remembered.
- `25G` and `25gg` go to a row; `Ctrl-w w` and `Ctrl-w =` switch pane and
  reset the pane sizes; `ZZ` quits.

### Changed

- A capture piped in on stdin does not take the terminal until packets
  arrive, so a `sudo` in the pipeline can ask for its password.
- **Marking a packet for `:marked` is now `M`**, since `m` begins a mark.
- The columns you arrange are remembered between runs. `:column reset` goes
  back to the Wireshark profile's.

### Fixed

- On Wireshark older than 4.2, `f` in a statistics table showed sharkd's
  raw error. It now says that filtered statistics need 4.2.

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

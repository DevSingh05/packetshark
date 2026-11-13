# packetshark

[![CI](https://github.com/DevSingh05/packetshark/actions/workflows/ci.yml/badge.svg)](https://github.com/DevSingh05/packetshark/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DevSingh05/packetshark)](https://github.com/DevSingh05/packetshark/releases/latest)
[![crates.io](https://img.shields.io/crates/v/packetshark)](https://crates.io/crates/packetshark)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

A terminal UI for Wireshark. Packet list, protocol details and bytes in three
panes, with display filters, stream following and statistics, in one small
binary that runs anywhere you have a shell.

packetshark does no dissection of its own. It drives **sharkd**, the JSON-RPC
daemon that ships with Wireshark, so every protocol, display filter, colouring
rule and preference Wireshark has works here, with the same results.

![A short recording: opening a capture, filtering for failed HTTP responses, following the stream of one, then expert information, the packets-over-time graph and sorting by length](docs/demo.gif)

![packetshark showing a TLS session it has decrypted: the packet list, the HTTP header selected in the details tree, and its bytes highlighted in the hex view](docs/screenshot.png)

## What it does

- **Three linked panes.** Select a field and its bytes light up; move the byte
  cursor and the field that owns the byte is selected. Reassembled and
  decrypted data appear as extra data sources. Any run of bytes can be
  selected and copied as hex, text, a C array or base64.
- **Display filters with live feedback.** The filter is checked as you type,
  field names complete with Tab, and an invalid filter is never applied.
- **Large captures.** Only the rows on screen are fetched, so a
  million-packet capture scrolls like a small one (see [Performance](#performance)).
- **Follow Stream** for TCP, UDP, TLS, HTTP, HTTP/2, QUIC and the rest, as
  text, hex dump or raw bytes; search it, save the payload or filter down to
  the stream.
- **Statistics**: conversations, endpoints, protocol hierarchy, expert
  information, per-protocol trees, exporting objects (HTTP, SMB, TFTP, ...),
  and the capture file's own properties.
- **Packets over time** as a bar chart you can step along and filter from,
  and a **flow sequence** (call flow) of who sent what to whom.
- **Find** in packet bytes, in the details or in the summary, as text, a
  regular expression, hex or a filter expression, with the match pointed
  out where it lands; **go to** a packet; vim-style
  **marks** (`ma`, `'a`, `''`), including ones that remember their capture
  file; **time references**.
- **A command line that completes** commands, their arguments and file
  names with Tab.
- **Apply or prepare a filter** from any field, and **copy** values, filters
  or bytes to the clipboard (using OSC 52, so it works over SSH; or through
  a command such as `xclip`, where the terminal cannot).
- **Live capture** through `dumpcap`, a capture **piped in on stdin**, or a
  file that another program is still writing.
- **Your Wireshark profile**: columns, colouring rules, preferences and
  Decode As rules are picked up as they are. `-C` or `:profile` selects
  another profile, and `:decode tcp.port 8080 http` (or `-d`) adds a Decode
  As rule without touching your Wireshark configuration.
- **Sorting**: `:sort length desc`, or a click on a column's title, sorts
  the packet list by that column.
- **Your own columns**: press `C` on any field to add it as a column, or
  `:column http.host Host`. `:columns` opens an editor to reorder, hide,
  rename and delete them, and the arrangement is remembered.
- Mouse support, two layouts, zoom, and a `?` key that lists everything; the
  status bar shows the keys that matter where you are.
- **Works on plain terminals**: ASCII drawing when the locale is not UTF-8,
  no colour when `NO_COLOR` is set, light and dark backgrounds.

## Install

With Homebrew, on macOS or Linux. This installs Wireshark's command-line
tools as well:

```sh
brew install DevSingh05/tap/packetshark
```

Or download a binary from the
[releases page](https://github.com/DevSingh05/packetshark/releases). The Linux
ones are static and run on any distribution. Or build it with Rust 1.88 or
newer:

```sh
cargo install packetshark
```

On macOS, prefer Homebrew. The release binaries are not signed with an Apple
developer certificate, so one downloaded with a browser is blocked the first
time it is run. If you do download one, clear the block with:

```sh
xattr -d com.apple.quarantine packetshark
```

However you install it, packetshark needs Wireshark's command-line tools.
`sharkd` is required; `dumpcap` is used for live capture and `tshark` for
saving filtered packets.

| System           | Command                          |
| ---------------- | -------------------------------- |
| macOS (Homebrew) | `brew install wireshark`         |
| Debian, Ubuntu   | `sudo apt install tshark`        |
| Fedora           | `sudo dnf install wireshark-cli` |
| Arch             | `sudo pacman -S wireshark-cli`   |

If `sharkd` is somewhere unusual, point to it with `--sharkd PATH`, the
`PACKETSHARK_SHARKD` environment variable, or `sharkd = "..."` in the config
file.

Wireshark 3.6 and newer work. The test suite runs against 3.6, 4.0, 4.2 and
4.6, which are what Ubuntu 22.04, Debian 12, Ubuntu 24.04 and current
systems ship.

## Use

```sh
packetshark capture.pcapng                    # open a capture
packetshark -Y 'http && ip.addr == 10.0.0.1' capture.pcapng
packetshark -i en0                            # capture live (see below)
packetshark -i en0 -f 'port 53'               # ... with a capture filter
packetshark -i en0 -w kept.pcapng             # ... and keep the packets
ssh host tcpdump -U -w - | packetshark -      # capture on another machine
packetshark --tail growing.pcap               # follow a file being written
packetshark --keylog keys.log tls.pcapng      # decrypt TLS
packetshark -D                                # list capture interfaces
packetshark                                   # choose an interface from a list
packetshark -t ad capture.pcapng              # times as date and time of day
packetshark -d tcp.port==8080,http x.pcapng   # Decode As, as in tshark
packetshark -C work capture.pcapng            # a Wireshark configuration profile
packetshark -Y dns capture.pcapng | less      # no terminal: print like tshark
```

A capture read from stdin leaves the terminal alone until packets arrive, so
`sudo tcpdump -U -w - | packetshark -` can ask for its password first. The
packets of a live or piped capture are kept only if you give `-w FILE`;
otherwise `:write FILE` saves them before you quit. `:restart` drops what
has been captured and starts the capture again. Ctrl-z suspends
packetshark as it does any program, and `fg` brings it back.

Press `?` inside packetshark for the keys. `packetshark --help` lists the options.

### A worked example: "the app is slow and sometimes fails"

You have a capture taken while it was happening. Four moves find most
network problems:

1. **`S` then `x`: expert information.** Wireshark's own list of what looked
   wrong, most serious first, each message once with a count. Retransmissions,
   resets and unanswered DNS queries show up here. Press Enter on a line to
   list the packets behind it.
2. **`S` then `c`: conversations.** Press `o` to sort by duration or bytes.
   A connection that lasted seconds and carried nothing back is a port that
   is being dropped.
3. **Filter for failures and add the timing as a column.**
   `/http.response.code >= 400` lists the errors, and `:column http.time`
   shows how long each took to arrive. For DNS, `/dns` with
   `:column dns.time`.
4. **`F` on a suspicious packet** follows its whole stream, so you can read
   what was actually said before it broke.

When you have found it, a filter such as
`tcp.analysis.retransmission || tcp.flags.reset == 1` followed by
`:write evidence.pcapng` saves just those packets to send to someone else.

### Live capture permissions

Capturing needs access to the network devices, which packetshark leaves to
`dumpcap` exactly as Wireshark does. Without it you get dumpcap's own error
and a hint:

- macOS: `brew install --cask wireshark-chmodbpf`
- Linux: `sudo usermod -aG wireshark $USER`, then log in again

## Keys

**Everywhere**

| Key                  | Action                                          |
| -------------------- | ----------------------------------------------- |
| `?`                  | Show or hide this help                          |
| `q`                  | Quit (or close the current window)              |
| `Tab / Shift-Tab`    | Next / previous pane                            |
| `1 2 3`              | Go to packet list / details / bytes             |
| `/`                  | Edit the display filter                         |
| `x`                  | Clear the display filter                        |
| `:`                  | Command line (try :help)                        |
| `s`                  | Find a packet: in its bytes, details or summary |
| `n / N`              | Next / previous match                           |
| `Esc`                | Stop a search that is still running             |
| `z`                  | Zoom the current pane                           |
| `L`                  | Switch layout (stacked / side by side)          |
| `+ / -`              | Grow / shrink the current pane                  |
| `Ctrl-w w, Ctrl-w =` | Next pane; reset the pane sizes                 |
| `ZZ`                 | Quit                                            |
| `Ctrl-r`             | Reload the capture                              |
| `Ctrl-c`             | Stop a live capture, or quit                    |
| `Ctrl-z`             | Suspend to the shell (fg comes back)            |

**Moving**

| Key                            | Action                                         |
| ------------------------------ | ---------------------------------------------- |
| `j / k, ↓ / ↑`                 | Down / up                                      |
| `PgDn / PgUp, Ctrl-d / Ctrl-u` | Page down / up                                 |
| `g / G, Home / End`            | First / last                                   |
| `25G, 25gg`                    | Go to row 25 of the pane                       |
| `ma … mz`                      | Set a mark on the packet                       |
| `mA … mZ`                      | Set a mark that remembers the file and is kept |
| `'a`                           | Go to a mark, opening its file if need be      |
| `''`                           | Go back to where you were before the last jump |
| `Mouse`                        | Click to select, wheel to scroll               |

**Packet list**

| Key      | Action                                         |
| -------- | ---------------------------------------------- |
| `Enter`  | Go to the details pane                         |
| `M`      | Mark or unmark the packet (:marked lists them) |
| `Ctrl-t` | Set or clear a time reference                  |
| `t`      | Change the time format                         |
| `c`      | Change row colouring (Wireshark / tint / off)  |
| `F`      | Follow the packet's stream                     |
| `S`      | Statistics menu                                |
| `:123`   | Go to packet 123                               |

**Packet details**

| Key            | Action                                                 |
| -------------- | ------------------------------------------------------ |
| `Enter, Space` | Expand or collapse; follow a packet link               |
| `l / h, → / ←` | Expand / collapse (or go to the parent)                |
| `*`            | Expand everything under the field                      |
| `e`            | Expand or collapse the whole tree                      |
| `a`            | Apply the field as a filter                            |
| `C`            | Add the field as a column in the packet list           |
| `p`            | Prepare a filter from the field (edit before applying) |
| `y`            | Copy the field (value, filter, bytes, ...)             |

**Packet bytes**

| Key               | Action                                                 |
| ----------------- | ------------------------------------------------------ |
| `h j k l, arrows` | Move the byte cursor; the matching field is selected   |
| `[ / ]`           | Previous / next data source (reassembled, decrypted)   |
| `v`               | Select bytes from here: move to extend, y to copy them |
| `y`               | Copy bytes                                             |

**Filter bar**

| Key               | Action                                        |
| ----------------- | --------------------------------------------- |
| `Enter`           | Apply                                         |
| `Esc`             | Cancel                                        |
| `Tab`             | Complete the field name                       |
| `↑ / ↓`           | Choose a completion, or browse recent filters |
| `Ctrl-u / Ctrl-w` | Clear the line / delete a word                |

**Follow stream**

| Key     | Action                                           |
| ------- | ------------------------------------------------ |
| `/`     | Search the stream: text, or /regex/              |
| `n / N` | Next / previous match in the stream              |
| `m`     | Change mode (ASCII / hex dump / raw)             |
| `d`     | Show both directions / client only / server only |
| `f`     | Filter the packet list to this stream            |
| `Enter` | Go to the packet at the top of the view          |
| `w`     | Save the payload to a file                       |
| `y`     | Copy the text                                    |

**Statistics**

| Key               | Action                                                      |
| ----------------- | ----------------------------------------------------------- |
| `Enter`           | Filter to the row, go to its packet, or save the object     |
| `Tab / Shift-Tab` | Next / previous protocol                                    |
| `o / r`           | Sort by the next column / reverse the order                 |
| `f`               | Count only packets matching the display filter              |
| `a / p`           | Apply / prepare a filter from the row: one way, or combined |

**Packets over time (:graph)**

| Key            | Action                                   |
| -------------- | ---------------------------------------- |
| `h / l, ← / →` | Move along the bars                      |
| `Enter`        | Filter the packet list to the bar's time |
| `+ / -`        | Finer / coarser bars                     |
| `b`            | Bytes instead of packets, and back       |

**Column editor**

| Key     | Action                                     |
| ------- | ------------------------------------------ |
| `Space` | Show or hide the column                    |
| `J / K` | Move the column down / up                  |
| `r`     | Rename it                                  |
| `a`     | Add a column for a field                   |
| `b`     | Add one of the built-in column types       |
| `d`     | Delete it                                  |
| `R`     | Go back to the Wireshark profile's columns |

**Commands**

| Key                               | Action                                                              |
| --------------------------------- | ------------------------------------------------------------------- |
| `:<number>`                       | Go to a packet                                                      |
| `:filter <expr>`                  | Apply a display filter                                              |
| `:clear`                          | Clear the display filter                                            |
| `:conv [proto]`                   | Conversations (eth, ipv4, ipv6, tcp, udp)                           |
| `:endpoints [proto]`              | Endpoints                                                           |
| `:phs`                            | Protocol hierarchy                                                  |
| `:expert`                         | Expert information                                                  |
| `:graph`                          | Packets over time                                                   |
| `:flow [proto]`                   | Flow sequence: who sent what to whom (all, tcp, icmp)               |
| `:objects [proto]`                | Exportable objects (http, smb, tftp, imf, ...)                      |
| `:stat <name>`                    | A protocol's statistics tree (http, http_req, dns, rtsp, ...)       |
| `:follow [proto]`                 | Follow the selected packet's stream                                 |
| `:write <file>`                   | Save the displayed packets                                          |
| `:columns`                        | Arrange the columns: order, visibility, titles                      |
| `:sort [column] [desc]`           | Sort the packets by a column, or click its title (:sort off undoes) |
| `:column <field> [title]`         | Add a column showing a field                                        |
| `:column remove <name>`           | Remove a column by its title or field                               |
| `:column reset`                   | Go back to the Wireshark profile's columns                          |
| `:marked`                         | Show only marked packets                                            |
| `:marks`                          | List the marks set with m, and go to one                            |
| `:unmark`                         | Remove all marks                                                    |
| `:keylog <file>`                  | Decrypt TLS with a key log file                                     |
| `:decode <table> <value> <proto>` | Decode As, e.g. :decode tcp.port 8080 http (:decode clear undoes)   |
| `:profile [name]`                 | Switch Wireshark configuration profile (a list, without a name)     |
| `:set <pref> <value>`             | Set a Wireshark preference                                          |
| `:time <format>`                  | relative, delta, absolute, date, utc, utc-date, default             |
| `:map <key> <keys>`               | Make a key type a sequence of keys                                  |
| `:unmap <key>`                    | Remove a key mapping (:map lists them)                              |
| `:theme [name]`                   | Choose a colour theme (a list, without a name)                      |
| `:colors <mode>`                  | Packet row colours: wireshark, tint, off                            |
| `:layout <name>`                  | stacked, side                                                       |
| `:open <file>`                    | Open another capture                                                |
| `:recent`                         | Open a capture opened lately                                        |
| `:info`                           | The capture file's properties: format, size, time span              |
| `:reload`                         | Reload the capture                                                  |
| `:stop`                           | Stop a live capture                                                 |
| `:restart`                        | Start a live capture again, dropping its packets                    |
| `:quit`                           | Quit                                                                |

Typing after `/` replaces the current filter; press an arrow key first to
edit it instead.

## Configuration

`~/.config/packetshark/config.toml` (or `$XDG_CONFIG_HOME/packetshark/config.toml`,
or the file named by `PACKETSHARK_CONFIG`). Every key is optional; see
[`config.example.toml`](config.example.toml).

```toml
sharkd = "/opt/wireshark/bin/sharkd"   # default: found automatically
profile = "work"                       # Wireshark configuration profile

[ui]
row_colors = "wireshark"   # wireshark | tint | off
layout = "stacked"         # stacked | side
background = "auto"        # dark | light | auto (used by "tint")
mouse = true
expand_all = false         # start with the details tree fully open
ascii = false              # draw with ASCII only (automatic without UTF-8)
theme = "nord"             # colour theme, until you choose one with :theme
copy_command = ["pbcopy"]  # program that copied text is piped to
```

Recent filters are remembered in `~/.local/state/packetshark/filters`, and
choices made while running (the theme and the columns, for two) in
`state.toml` beside it.
The config file is yours: packetshark reads it and never writes to it.

Row colours: `wireshark` paints rows with your colouring rules as the GUI
does. If that clashes with your terminal theme, `tint` colours only the text
and `off` uses none. `c` cycles through them.

### Key mappings

`:map` makes one key type a sequence of keys, and the mapping is remembered:

```
:map <f5> :conv<enter>         F5 opens the conversations
:map <C-s> /                   Ctrl-s starts a filter
:map T /tcp.analysis.retransmission<enter>
```

A printable key is written as itself; the others as `<enter>`, `<esc>`,
`<space>`, `<tab>`, `<bs>`, `<del>`, `<up>`, `<down>`, `<left>`, `<right>`,
`<pgup>`, `<pgdn>`, `<home>`, `<end>`, `<f1>` to `<f12>`, and `<lt>` for `<`.
`<C-x>` is Ctrl-x and `<A-x>` is Alt-x. `:map` on its own lists the mappings
and `:unmap <key>` removes one. A mapped key is not mapped inside another
mapping, and while you type a filter or a command it is just its character.

### Themes

`:theme` lists the themes and `:theme nord` switches to one; the choice is
remembered. `default` follows your terminal's own colours. The others set
every colour themselves: `dracula`, `gruvbox`, `nord`, `solarized-dark` and
`solarized-light`.

To make your own, put a file in `~/.config/packetshark/themes/`. Its name is
the theme's name, and it only needs to mention what it changes:

```toml
# ~/.config/packetshark/themes/mine.toml
dark = true                 # which default fills in what is left out

[colors]                    # names of your own, to use below
ink = "#102030"

[styles]
text = { fg = "#d0d0d0", bg = "ink" }      # everything not styled otherwise
selected = { fg = "white", bg = "#005f87", bold = true }
error = { fg = "208" }                     # a number from the 256 palette
```

A colour is `#rrggbb`, a terminal colour name (`red`, `lightblue`, `gray`,
...), a number from 0 to 255, or a name from `[colors]`. A style can also set
`bold`, `dim`, `italic`, `underline` and `reverse`. The parts that can be
styled are `text`, `dim`, `title`, `title_focused`, `rule`, `rule_focused`,
`column_header`, `selected`, `selected_unfocused`, `status`, `status_key`,
`popup`, `popup_selected`, `ok`, `warn`, `error`, `proto`, `generated`,
`link`, `hex_offset`, `hex_highlight`, `hex_cursor`, `marked`, `client`,
`server` and `bar`. A file with the name of a built-in theme replaces it.
Packet rows keep Wireshark's colouring-rule colours under every theme.

Terminals: the interface uses your terminal's own colours for its accents, so
it follows your theme. Set `background = "light"` if a light terminal is not
detected. With a locale that is not UTF-8 (or `--ascii`) it draws with ASCII
characters only, and with [`NO_COLOR`](https://no-color.org) set it uses
bold, dim and reverse video instead of colour.

## Performance

Measured with the release build on an Apple M5 Pro, Wireshark 4.6.9, and a
synthetic capture of 1,000,000 UDP packets (71 MB). To run it yourself:

```sh
PACKETSHARK_PERF_PCAP=big.pcap cargo test --release --test perf -- --ignored --nocapture
```

| Operation                                 | Time        |
| ----------------------------------------- | ----------- |
| Open (load and first screen)              | 4.6 s       |
| Move to the next packet, details included | under 50 ms |
| Jump to the last packet                   | under 50 ms |
| Apply a filter for the first time         | 5.4 s       |
| Apply a filter sharkd has seen before     | under 50 ms |
| Jump within a filtered list               | under 50 ms |

| Memory                                                 |              |
| ------------------------------------------------------ | ------------ |
| packetshark with the capture open                      | 5 MB         |
| sharkd with the capture open                           | about 0.9 GB |
| packetshark showing a table of 1,000,000 conversations | 120 MB       |

The slow steps are sharkd dissecting every packet: on load, and the first
time a filter is evaluated. The interface stays responsive while it works.
Statistics tables keep the 100,000 busiest rows and say when they have
dropped the rest.

## How it works

```
 keys, mouse ─▶ App ◀── replies ── worker thread ◀──▶ sharkd  (JSON-RPC over a pipe)
                 │                       ▲
                 └── requests ───────────┘            dumpcap ─▶ spool file (live capture)
```

- `src/sharkd/` is a small blocking JSON-RPC client and a worker thread that
  owns the sharkd process. Replies are parsed straight off the pipe into their
  final types. Requests that a newer one has made pointless (the details of a
  packet the cursor already left) are dropped before they reach sharkd. If
  sharkd crashes, it is restarted, the capture is reloaded and the request is
  retried once.
- `src/app/` is the application state. It consumes events and never touches
  the terminal, which is what lets the test suite drive the real app.
- `src/ui/` draws the state into a [ratatui](https://ratatui.rs) buffer.
- Live captures are written by `dumpcap` to a temporary file that packetshark
  reloads as it grows, backing off as reloads get slower.

## Limitations

- **Live capture reloads the whole file** each time it grows, because sharkd
  has no incremental load. That is fine for minutes of ordinary traffic and
  gets slower as a capture reaches hundreds of megabytes. For long sessions,
  capture to a file and open it afterwards.
- **Unix only so far.** It is developed on macOS and tested on macOS and
  Linux. Windows is untested, and Wireshark's Windows installer does not
  include sharkd.
- **Older Wireshark has less to offer.** Protocol hierarchy statistics need
  4.2 and time references need 4.0; packetshark says so when you ask for
  them. Before 4.2 the delta times in the details pane are relative to the
  previous packet in the file even when a filter hides it.
- Live capture was verified with a scripted stand-in for dumpcap, not against
  a real interface. TLS decryption is covered only by the optional
  real-capture walk (a capture with embedded secrets), not by the default
  test suite.
- No packet editing, and no VoIP or RTP analysis yet.

## Development

```sh
cargo test                                   # unit tests plus end-to-end tests
cargo clippy --all-targets -- -D warnings    # lints; the set is in Cargo.toml
cargo fmt                                    # Rust formatting (rustfmt.toml)
npx prettier@3 --write "**/*.{md,yml,yaml}"  # Markdown and YAML formatting
npx @taplo/cli@0.7 fmt                       # TOML formatting
```

CI runs all five and fails on any difference.

The end-to-end tests run the real app against sharkd and render it to an
in-memory terminal. They build their own capture files, so they need no
fixtures, privileges or network, and they are skipped when Wireshark is not
installed. `tests/docs.rs` fails if the key reference above drifts from the
in-app help.

`tests/monkey.rs` throws random keys, mouse events, pastes and resizes at the
app and fails if it panics or stops responding. The default run is short;
`PACKETSHARK_MONKEY_EVENTS=20000 cargo test --test monkey` runs for longer.

Two more tests are opt-in because they need files that are not in this
repository:

```sh
# Timings and memory on a large capture
PACKETSHARK_PERF_PCAP=big.pcap cargo test --release --test perf -- --ignored --nocapture

# Walk every packet of real captures (for example Wireshark's test/captures):
# details, bytes, follow, statistics, filters; fails on any error
PACKETSHARK_REAL_DIR=captures/ cargo test --release --test real -- --ignored --nocapture
```

## Contributing

Bug reports and patches are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Security problems are reported privately, as [SECURITY.md](SECURITY.md)
describes. Changes between releases are in [CHANGELOG.md](CHANGELOG.md).

## Credits and licence

packetshark follows the path cut by [termshark](https://github.com/gcla/termshark)
by Graham Clark, which showed how good Wireshark in a terminal can be.

MIT licensed; see [LICENSE](LICENSE). packetshark is not affiliated with the
Wireshark project. It runs Wireshark's tools as separate programs and links
none of Wireshark's code.

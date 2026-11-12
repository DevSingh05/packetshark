# Contributing

Bug reports, captures that misbehave, and patches are all welcome.

## Reporting a problem

Open an issue with:

- what you did and what you saw,
- `packetshark --version` and `sharkd -v`,
- your terminal and operating system,
- a capture that shows it, if you can share one. Captures often hold private
  data; `editcap` can cut one down to the packets that matter.

Security problems go through the private channel in [SECURITY.md](SECURITY.md),
not the issue tracker.

## Building and testing

You need Rust 1.88 or newer and Wireshark's command-line tools (`sharkd`).

```sh
cargo test                                   # unit tests plus end-to-end tests
cargo clippy --all-targets -- -D warnings
cargo fmt
npx prettier@3 --write "**/*.{md,yml,yaml}"
npx @taplo/cli@0.7 fmt
```

CI runs the same commands and fails on any difference. The end-to-end tests
drive the real app against the real sharkd and build their own capture files,
so they need no fixtures, network or privileges.

## What a good change looks like

- **A test that fails without it.** For anything a user can see, that is a
  test in `tests/app.rs`, which types keys and reads the screen.
- **It works on old Wireshark.** CI runs against 3.6, 4.0, 4.2 and 4.6, and
  sharkd differs between them in ways that have broken this project before.
  If you touch `src/sharkd`, expect to find out.
- **The README stays true.** `tests/docs.rs` fails if the key reference there
  drifts from the in-app help in `src/app/help.rs`.
- **One change per commit**, with a message that says why.

## How the code is laid out

| Path             | What it holds                                                |
| ---------------- | ------------------------------------------------------------ |
| `src/sharkd/`    | The sharkd process, its JSON-RPC replies, the worker thread  |
| `src/app/`       | State and behaviour: keys, commands, panes, windows          |
| `src/ui/`        | Drawing. It reads the app's state and never changes it       |
| `src/capture.rs` | Live capture through dumpcap, and captures piped in on stdin |
| `tests/common/`  | The test harness and a small pcap writer                     |

The app never talks to sharkd directly. It sends requests to a worker thread
and handles the replies as events, which is what keeps the interface
responsive while sharkd is busy with a large capture.

## Licence

By contributing you agree that your work is released under the
[MIT licence](LICENSE).

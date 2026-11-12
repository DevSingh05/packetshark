//! The key reference shown by `?`. It is also the source for the README's
//! key table, so the two cannot drift apart.

pub struct Section {
    pub title: &'static str,
    pub keys: &'static [(&'static str, &'static str)],
}

pub const SECTIONS: &[Section] = &[
    Section {
        title: "Everywhere",
        keys: &[
            ("?", "Show or hide this help"),
            ("q", "Quit (or close the current window)"),
            ("Tab / Shift-Tab", "Next / previous pane"),
            ("1 2 3", "Go to packet list / details / bytes"),
            ("/", "Edit the display filter"),
            ("x", "Clear the display filter"),
            (":", "Command line (try :help)"),
            ("s", "Find a packet (filter expression or plain text)"),
            ("n / N", "Next / previous match"),
            ("z", "Zoom the current pane"),
            ("L", "Switch layout (stacked / side by side)"),
            ("+ / -", "Grow / shrink the current pane"),
            ("Ctrl-r", "Reload the capture"),
            ("Ctrl-c", "Stop a live capture, or quit"),
        ],
    },
    Section {
        title: "Moving",
        keys: &[
            ("j / k, ↓ / ↑", "Down / up"),
            ("PgDn / PgUp, Ctrl-d / Ctrl-u", "Page down / up"),
            ("g / G, Home / End", "First / last"),
            ("Mouse", "Click to select, wheel to scroll"),
        ],
    },
    Section {
        title: "Packet list",
        keys: &[
            ("Enter", "Go to the details pane"),
            ("m", "Mark or unmark the packet"),
            ("Ctrl-t", "Set or clear a time reference"),
            ("t", "Change the time format"),
            ("c", "Change row colouring (Wireshark / tint / off)"),
            ("F", "Follow the packet's stream"),
            ("S", "Statistics menu"),
            (":123", "Go to packet 123"),
        ],
    },
    Section {
        title: "Packet details",
        keys: &[
            ("Enter, Space", "Expand or collapse; follow a packet link"),
            ("l / h, → / ←", "Expand / collapse (or go to the parent)"),
            ("*", "Expand everything under the field"),
            ("e", "Expand or collapse the whole tree"),
            ("a", "Apply the field as a filter"),
            ("C", "Add the field as a column in the packet list"),
            (
                "p",
                "Prepare a filter from the field (edit before applying)",
            ),
            ("y", "Copy the field (value, filter, bytes, ...)"),
        ],
    },
    Section {
        title: "Packet bytes",
        keys: &[
            (
                "h j k l, arrows",
                "Move the byte cursor; the matching field is selected",
            ),
            (
                "[ / ]",
                "Previous / next data source (reassembled, decrypted)",
            ),
            ("y", "Copy bytes"),
        ],
    },
    Section {
        title: "Filter bar",
        keys: &[
            ("Enter", "Apply"),
            ("Esc", "Cancel"),
            ("Tab", "Complete the field name"),
            ("↑ / ↓", "Choose a completion, or browse recent filters"),
            ("Ctrl-u / Ctrl-w", "Clear the line / delete a word"),
        ],
    },
    Section {
        title: "Follow stream",
        keys: &[
            ("m", "Change mode (ASCII / hex dump / raw)"),
            ("d", "Show both directions / client only / server only"),
            ("f", "Filter the packet list to this stream"),
            ("Enter", "Go to the packet at the top of the view"),
            ("w", "Save the payload to a file"),
            ("y", "Copy the text"),
        ],
    },
    Section {
        title: "Statistics",
        keys: &[
            (
                "Enter",
                "Filter to the row, go to its packet, or save the object",
            ),
            ("Tab / Shift-Tab", "Next / previous protocol"),
            ("o / r", "Sort by the next column / reverse the order"),
            ("f", "Count only packets matching the display filter"),
        ],
    },
    Section {
        title: "Column editor",
        keys: &[
            ("Space", "Show or hide the column"),
            ("J / K", "Move the column down / up"),
            ("r", "Rename it"),
            ("a", "Add a column for a field"),
            ("b", "Add one of the built-in column types"),
            ("d", "Delete it"),
            ("R", "Go back to the Wireshark profile's columns"),
        ],
    },
    Section {
        title: "Commands",
        keys: &[
            (":<number>", "Go to a packet"),
            (":filter <expr>", "Apply a display filter"),
            (":clear", "Clear the display filter"),
            (":conv [proto]", "Conversations (eth, ipv4, ipv6, tcp, udp)"),
            (":endpoints [proto]", "Endpoints"),
            (":phs", "Protocol hierarchy"),
            (":expert", "Expert information"),
            (
                ":objects [proto]",
                "Exportable objects (http, smb, tftp, imf, ...)",
            ),
            (
                ":stat <name>",
                "A protocol's statistics tree (http, http_req, dns, rtsp, ...)",
            ),
            (":follow [proto]", "Follow the selected packet's stream"),
            (":write <file>", "Save the displayed packets"),
            (":columns", "Arrange the columns: order, visibility, titles"),
            (":column <field> [title]", "Add a column showing a field"),
            (
                ":column remove <name>",
                "Remove a column by its title or field",
            ),
            (
                ":column reset",
                "Go back to the Wireshark profile's columns",
            ),
            (":marked", "Show only marked packets"),
            (":unmark", "Remove all marks"),
            (":keylog <file>", "Decrypt TLS with a key log file"),
            (":set <pref> <value>", "Set a Wireshark preference"),
            (
                ":time <format>",
                "relative, delta, absolute, date, utc, utc-date, default",
            ),
            (
                ":theme [name]",
                "Choose a colour theme (a list, without a name)",
            ),
            (":colors <mode>", "Packet row colours: wireshark, tint, off"),
            (":layout <name>", "stacked, side"),
            (":open <file>", "Open another capture"),
            (":reload", "Reload the capture"),
            (":stop", "Stop a live capture"),
            (":quit", "Quit"),
        ],
    },
];

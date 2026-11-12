//! Builds small, valid pcap files for tests, so the suite needs no binary
//! fixtures and no network access.

#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::path::Path;

pub const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
pub const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
pub const RESOLVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLIENT_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
const ROUTER_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ethernet(from_client: bool, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let (src, dst) = if from_client {
        (CLIENT_MAC, ROUTER_MAC)
    } else {
        (ROUTER_MAC, CLIENT_MAC)
    };
    let mut out = Vec::with_capacity(14 + payload.len());
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x45, 0];
    h.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 1, 0x40, 0, 64, protocol, 0, 0]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let sum = checksum(&h);
    h[10..12].copy_from_slice(&sum.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

#[allow(clippy::too_many_arguments)]
fn tcp_segment(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut h = Vec::with_capacity(20 + data.len());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&seq.to_be_bytes());
    h.extend_from_slice(&ack.to_be_bytes());
    h.extend_from_slice(&[5 << 4, flags]);
    h.extend_from_slice(&65535u16.to_be_bytes());
    h.extend_from_slice(&[0, 0, 0, 0]);
    h.extend_from_slice(data);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(h.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&h);
    let sum = checksum(&pseudo);
    h[16..18].copy_from_slice(&sum.to_be_bytes());
    h
}

fn udp_datagram(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(8 + data.len());
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&dport.to_be_bytes());
    h.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0]);
    h.extend_from_slice(data);
    h
}

fn dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A capture under construction. Packets are 12.3 ms apart, starting at a
/// fixed time, so every run produces the same file.
#[derive(Default)]
pub struct Pcap {
    packets: Vec<Vec<u8>>,
}

impl Pcap {
    pub fn new() -> Pcap {
        Pcap::default()
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn raw(&mut self, frame: Vec<u8>) -> &mut Self {
        self.packets.push(frame);
        self
    }

    /// A DNS A query and its answer.
    pub fn dns(&mut self, name: &str, answer: Ipv4Addr) -> &mut Self {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend(dns_name(name));
        query.extend_from_slice(&[0, 1, 0, 1]);
        let mut reply = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        reply.extend(dns_name(name));
        reply.extend_from_slice(&[0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4]);
        reply.extend_from_slice(&answer.octets());
        self.udp(true, RESOLVER, 5353, 53, &query);
        self.udp(false, RESOLVER, 53, 5353, &reply)
    }

    /// One UDP datagram between the client and `peer`.
    pub fn udp(
        &mut self,
        from_client: bool,
        peer: Ipv4Addr,
        sport: u16,
        dport: u16,
        data: &[u8],
    ) -> &mut Self {
        let (src, dst) = if from_client {
            (CLIENT, peer)
        } else {
            (peer, CLIENT)
        };
        let frame = ethernet(
            from_client,
            0x0800,
            &ipv4(src, dst, 17, &udp_datagram(sport, dport, data)),
        );
        self.raw(frame)
    }

    /// A complete TCP conversation: handshake, one request, one response, and
    /// an orderly close: nine packets.
    pub fn tcp_exchange(
        &mut self,
        client_port: u16,
        server_port: u16,
        request: &[u8],
        response: &[u8],
    ) -> &mut Self {
        let (c, s) = (CLIENT, SERVER);
        let (cp, sp) = (client_port, server_port);
        let (ci, si) = (1000u32, 5000u32);
        let rl = request.len() as u32;
        let pl = response.len() as u32;
        let seg =
            |this: &mut Self, from_client: bool, seq: u32, ack: u32, flags: u8, data: &[u8]| {
                let segment = if from_client {
                    tcp_segment(c, s, cp, sp, seq, ack, flags, data)
                } else {
                    tcp_segment(s, c, sp, cp, seq, ack, flags, data)
                };
                let (src, dst) = if from_client { (c, s) } else { (s, c) };
                this.raw(ethernet(from_client, 0x0800, &ipv4(src, dst, 6, &segment)));
            };
        seg(self, true, ci, 0, TCP_SYN, &[]);
        seg(self, false, si, ci + 1, TCP_SYN | TCP_ACK, &[]);
        seg(self, true, ci + 1, si + 1, TCP_ACK, &[]);
        seg(self, true, ci + 1, si + 1, TCP_PSH | TCP_ACK, request);
        seg(self, false, si + 1, ci + 1 + rl, TCP_ACK, &[]);
        seg(
            self,
            false,
            si + 1,
            ci + 1 + rl,
            TCP_PSH | TCP_ACK,
            response,
        );
        seg(self, true, ci + 1 + rl, si + 1 + pl, TCP_FIN | TCP_ACK, &[]);
        seg(
            self,
            false,
            si + 1 + pl,
            ci + 2 + rl,
            TCP_FIN | TCP_ACK,
            &[],
        );
        seg(self, true, ci + 2 + rl, si + 2 + pl, TCP_ACK, &[]);
        self
    }

    /// An HTTP GET and a 200 response carrying `body`.
    pub fn http(&mut self, client_port: u16, host: &str, path: &str, body: &str) -> &mut Self {
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test-client/1\r\n\r\n");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        self.tcp_exchange(client_port, 80, request.as_bytes(), response.as_bytes())
    }

    /// Like `http`, but the response arrives in two TCP segments, so the
    /// second one carries a reassembled data source.
    pub fn http_split(
        &mut self,
        client_port: u16,
        host: &str,
        path: &str,
        body: &str,
    ) -> &mut Self {
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (request, response) = (request.as_bytes(), response.as_bytes());
        let (first, second) = response.split_at(response.len() / 2);
        let (c, s, cp, sp) = (CLIENT, SERVER, client_port, 80u16);
        let (ci, si) = (1000u32, 5000u32);
        let rl = request.len() as u32;
        let seg =
            |this: &mut Self, from_client: bool, seq: u32, ack: u32, flags: u8, data: &[u8]| {
                let segment = if from_client {
                    tcp_segment(c, s, cp, sp, seq, ack, flags, data)
                } else {
                    tcp_segment(s, c, sp, cp, seq, ack, flags, data)
                };
                let (src, dst) = if from_client { (c, s) } else { (s, c) };
                this.raw(ethernet(from_client, 0x0800, &ipv4(src, dst, 6, &segment)));
            };
        seg(self, true, ci, 0, TCP_SYN, &[]);
        seg(self, false, si, ci + 1, TCP_SYN | TCP_ACK, &[]);
        seg(self, true, ci + 1, si + 1, TCP_ACK, &[]);
        seg(self, true, ci + 1, si + 1, TCP_PSH | TCP_ACK, request);
        seg(self, false, si + 1, ci + 1 + rl, TCP_ACK, first);
        seg(
            self,
            false,
            si + 1 + first.len() as u32,
            ci + 1 + rl,
            TCP_PSH | TCP_ACK,
            second,
        );
        seg(
            self,
            true,
            ci + 1 + rl,
            si + 1 + response.len() as u32,
            TCP_ACK,
            &[],
        );
        self
    }

    /// An ARP request for the router.
    pub fn arp(&mut self) -> &mut Self {
        let mut p = vec![0, 1, 8, 0, 6, 4, 0, 1];
        p.extend_from_slice(&CLIENT_MAC);
        p.extend_from_slice(&CLIENT.octets());
        p.extend_from_slice(&[0; 6]);
        p.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&CLIENT_MAC);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&p);
        self.raw(frame)
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        for (i, packet) in self.packets.iter().enumerate() {
            out.extend(record(i, packet));
        }
        out
    }

    pub fn write(&self, path: &Path) {
        std::fs::write(path, self.bytes()).unwrap();
    }
}

/// The pcap record for packet number `index` (zero-based).
pub fn record(index: usize, packet: &[u8]) -> Vec<u8> {
    let micros = 1_700_000_000_000_000u64 + (index as u64 + 1) * 12_300;
    let mut out = Vec::with_capacity(16 + packet.len());
    out.extend_from_slice(&((micros / 1_000_000) as u32).to_le_bytes());
    out.extend_from_slice(&((micros % 1_000_000) as u32).to_le_bytes());
    out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
    out.extend_from_slice(packet);
    out
}

/// The standard small capture: DNS lookup, an HTTP exchange, an ARP request
/// and a second HTTP exchange. 21 packets:
///
/// 1-2 DNS, 3-11 HTTP (GET in 6, 200 in 8), 12 ARP, 13-21 HTTP (GET in 16, 200 in 18).
pub fn web() -> Pcap {
    let mut p = Pcap::new();
    p.dns("example.com", SERVER);
    p.http(
        40000,
        "example.com",
        "/index.html",
        "<html><body>hello world</body></html>",
    );
    p.arp();
    p.http(
        40001,
        "example.com",
        "/about.html",
        "<html><body>about us</body></html>",
    );
    p
}

/// `n` UDP packets with distinct payload sizes, for scrolling tests.
pub fn many(n: usize) -> Pcap {
    let mut p = Pcap::new();
    for i in 0..n {
        let payload = format!("packet-{i:06}");
        p.udp(
            i % 2 == 0,
            RESOLVER,
            30000 + (i % 1000) as u16,
            9999,
            payload.as_bytes(),
        );
    }
    p
}

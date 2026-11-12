//! Talking to `sharkd`, Wireshark's JSON-RPC dissection daemon.

pub mod client;
pub mod types;
pub mod worker;

pub use client::{Client, Error, Launch, locate, version};
pub use worker::{DetailsStep, Purpose, Reply, Request, Seek, Worker};

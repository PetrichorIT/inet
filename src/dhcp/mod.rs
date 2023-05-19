//! The Dynamic-Host-Configuration Protocol (DHCP)
use des::net::message::MessageKind;

mod client;
mod common;
mod server;

pub use client::DHCPClient;
pub use common::DHCPMessage;

pub use server::DHCPServer;
pub use server::DHCPServerConfig;

pub const MESSAGE_KIND_DHCP: MessageKind = 0x63_82;

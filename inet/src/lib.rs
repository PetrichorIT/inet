#![feature(int_roundings)]

#[macro_use]
mod macros;

pub mod arp;
pub mod dns;
pub mod icmp;
pub mod interface;
pub mod io;
pub mod routing;
pub mod socket;
pub mod utils;

cfg_pcap! {
    pub mod pcap;
}

cfg_dhcp! {
    pub mod dhcp;
}

cfg_uds! {
    pub mod uds;
    pub mod fs;
}

pub use inet_types as types;

mod udp;
use des::net::plugin::PluginPanicPolicy;
pub use udp::*;

pub mod tcp;
pub use tcp::api::{TcpListener, TcpSocket, TcpStream};

mod plugin;
pub use plugin::*;

mod ctx;
pub use ctx::Current;
use ctx::*;

/// Initaliztion function for inet-plugins.
///
/// Call this function as the first step in your simulation (pre runtime creation)
pub fn init() {
    des::net::module::set_setup_fn(inet_init)
}

fn inet_init(this: &des::net::module::ModuleContext) {
    this.add_plugin(IOPlugin::new(), 1, PluginPanicPolicy::Abort);
}
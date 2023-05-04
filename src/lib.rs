#![feature(int_roundings)]

#[macro_use]
mod macros;

pub mod arp;
pub mod debug;
pub mod dhcp;
pub mod dns;
pub mod fs;
pub mod interface;
pub mod pcap;
pub mod routing;
pub mod socket;
pub mod uds;
pub mod utils;

mod udp;
use des::net::plugin::PluginPanicPolicy;
pub use udp::*;

pub mod tcp;
pub use tcp::api::{TcpListener, TcpSocket, TcpStream};

mod plugin;
pub use plugin::*;

mod ctx;
pub use ctx::*;

/// Initaliztion function for inet-plugins.
///
/// Call this function as the first step in your simulation (pre runtime creation)
pub fn init() {
    des::net::module::set_setup_fn(inet_init)
}

fn inet_init(this: &des::net::module::ModuleContext) {
    this.add_plugin(IOPlugin::new(), 50, PluginPanicPolicy::Abort);
    this.add_plugin(
        des::net::plugin::TokioTimePlugin::new("inet::imported_time_module".to_string()),
        1,
        PluginPanicPolicy::Abort,
    );
}

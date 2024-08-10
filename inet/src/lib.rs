#[macro_use]
mod macros;

pub mod arp;
pub mod dns;
pub mod extensions;
pub mod icmp;
pub mod interface;
pub mod io;
pub mod ipv6;
pub mod routing;
pub mod socket;
pub mod utils;

cfg_libpcap! {
    pub mod libpcap;
}

cfg_dhcp! {
    pub mod dhcp;
}

cfg_uds! {
    pub mod uds;
    pub mod fs;
}

use des::net::{module::ModuleId, processing::ProcessingStack};
pub use inet_types as types;

mod udp;
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
#[must_use]
pub fn init() -> ProcessingStack {
    ProcessingStack::from(IOPlugin::new(ModuleId::NULL))
}

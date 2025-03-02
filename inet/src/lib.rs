#[macro_use]
mod macros;

pub mod arp;
pub mod dns;
pub mod extensions;
pub mod fs;
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

cfg_test_util! {
    pub mod test_util;
}

use des::net::{module::ModuleId, processing::ProcessingStack};
use dns::DnsResolver;
pub use types;

mod udp;
pub use udp::*;

pub mod tcp;
pub use tcp::api::{TcpListener, TcpSocket, TcpStream};

pub mod tcp2;

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
    ProcessingStack::from(IOPlugin::new(IOContext::new(ModuleId::NULL)))
}

pub fn stack(
    dns_hook: DnsResolver,
    // on_startup: impl Fn() -> () + 'static,
) -> Box<dyn FnMut() -> ProcessingStack + 'static> {
    // let on_startup = Arc::new(on_startup);
    Box::new(move || {
        let mut io = IOContext::new(ModuleId::NULL);
        io.dns = dns_hook;
        ProcessingStack::from(IOPlugin::new(io))
    })
}

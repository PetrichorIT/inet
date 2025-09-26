#![allow(clippy::unit_arg)]

#[macro_use]
mod macros;

pub mod dns;
pub mod extensions;
pub mod interface;
pub mod io;
pub mod socket;
pub mod utils;

pub mod env;

pub mod ipv4;
pub mod ipv6;

cfg_libpcap! {
    pub mod libpcap;
}

cfg_dhcp! {
    pub mod dhcp;
}

pub mod test_util;

use des::net::{
    module::ModuleId,
    processing::{ProcessingStack, TimeDriver, TokioRuntime},
};
use dns::DnsResolver;
pub use types;

mod udp;
pub use udp::*;

pub mod tcp;

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
    (
        TimeDriver::default(),
        IOPlugin::new(IOContext::new(ModuleId::NULL)),
        TokioRuntime::default(),
    )
        .into()
}

pub fn stack(
    dns_hook: DnsResolver,
    // on_startup: impl Fn() -> () + 'static,
) -> Box<dyn FnMut() -> ProcessingStack + 'static> {
    // let on_startup = Arc::new(on_startup);
    Box::new(move || {
        let mut io = IOContext::new(ModuleId::NULL);
        io.dns = dns_hook;
        (
            TimeDriver::default(),
            IOPlugin::new(io),
            TokioRuntime::default(),
        )
            .into()
    })
}

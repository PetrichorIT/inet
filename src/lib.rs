#![feature(int_roundings)]

mod common;
pub use common::*;

#[macro_use]
mod macros;

pub mod dhcp;
pub mod dns;
pub mod inet;
pub mod ip;
pub mod routing;

// pub mod net;

pub fn init() {
    des::net::module::set_setup_fn(inet_init)
}

fn inet_init(this: &des::net::module::ModuleContext) {
    this.add_plugin(self::inet::IOPlugin::new(), 50, false);
}

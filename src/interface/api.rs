use super::Interface;
use crate::IOContext;

pub fn add_interface(iface: Interface) {
    IOContext::with_current(|ctx| ctx.add_interface(iface))
}

pub fn get_interfaces() -> Vec<Interface> {
    IOContext::with_current(|ctx| ctx.get_interfaces())
}

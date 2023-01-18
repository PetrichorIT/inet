use super::Interface;
use crate::IOContext;
use std::{io::Result, net::IpAddr};

pub fn add_interface(iface: Interface) {
    IOContext::with_current(|ctx| ctx.add_interface(iface))
}

pub fn get_interfaces() -> Vec<Interface> {
    IOContext::with_current(|ctx| ctx.get_interfaces())
}

pub fn get_mac_address() -> Result<Option<[u8; 6]>> {
    IOContext::with_current(|ctx| ctx.get_mac_address())
}

pub fn get_ip() -> Option<IpAddr> {
    IOContext::with_current(|ctx| ctx.get_ip())
}

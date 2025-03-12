use std::net::{Ipv4Addr, Ipv6Addr};

use super::{InterfaceFlags, InterfaceName, NetworkDevice};

pub struct InterfaceDef {
    pub name: InterfaceName,
    pub flags: InterfaceFlags,
    pub mtu: usize,
    pub device: NetworkDevice,
    pub addrs: InterfaceAddrs,
}

pub struct InterfaceAddrs {
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

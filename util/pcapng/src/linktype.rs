#![allow(unused)]

/// The linktype of an interface, defined in PCAPNG files.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Linktype(pub(crate) u16);

impl Linktype {
    /// Unknown link typ.
    pub const NULL: Linktype = Linktype(0);
    /// Ethernet link type.
    pub const ETHERNET: Linktype = Linktype(1);

    /// `FDDI` link type.
    pub const FDDI: Linktype = Linktype(10);
    /// Raw network access link type.
    pub const RAW: Linktype = Linktype(101);
    /// Loopback link type.
    pub const LOOP: Linktype = Linktype(108);
    /// `LINUX_SSL` link type.
    pub const LINUX_SSL: Linktype = Linktype(113);
    /// `IPV4` direct streams link type.
    pub const IPV4: Linktype = Linktype(228);
    /// `IPV6` direct streams link type.
    pub const IPV6: Linktype = Linktype(229);
    /// `NFLOG` link type.
    pub const NFLOG: Linktype = Linktype(239);
    /// `WIRESHARK_UPPER_LAYER_DPU` link type.
    pub const WIRESHARK_UPPER_LAYER_DPU: Linktype = Linktype(252);
}

#![allow(unused)]

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Linktype(pub(crate) u16);

impl Linktype {
    pub const NULL: Linktype = Linktype(0);
    pub const ETHERNET: Linktype = Linktype(1);

    pub const FDDI: Linktype = Linktype(10);
    pub const RAW: Linktype = Linktype(101);
    pub const LOOP: Linktype = Linktype(108);
    pub const LINUX_SSL: Linktype = Linktype(113);
    pub const IPV4: Linktype = Linktype(228);
    pub const IPV6: Linktype = Linktype(229);
    pub const NFLOG: Linktype = Linktype(239);
    pub const WIRESHARK_UPPER_LAYER_DPU: Linktype = Linktype(252);
}

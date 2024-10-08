use std::net::Ipv4Addr;

type RouterID = u32;
type AreaID = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfPacket {
    // version = 2
    pub typ: OspfPacketType,
    // length: u16
    pub router_id: RouterID,
    pub area_id: AreaID,
    // checksum: u16,
    // au_type: u16
    // u64 auth
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfPacketType {
    Hello(OspfHelloPacket),
    DatabaseDescription(OspfDatabaseDescriptionPacket),
    LinkStateRequest,
    LinkStateUpdate,
    LinkStateAck,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfHelloPacket {
    pub netmask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: OspfOptions,
    pub router_priority: u8,
    pub router_dead_interval: u32,
    pub designated_router_id: u32,
    pub backup_router_id: u32,
    pub neighbor_ids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfDatabaseDescriptionPacket {
    pub interface_mtu: u16,
    pub hello_interval: u8,
    pub options: OspfOptions,
    pub flags: u8,
    pub dd_sequence_number: u32,
    pub lsas: Vec<Lsa>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfOptions {
    pub external: bool,
    pub multicast: bool,
    pub np: bool,
    pub external_attributes_allowed: bool,
    pub demand_circuits: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfLinkStateRequestPacket {
    pub ls_typ: LsType,
    pub link_state_id: u32,
    pub advertising_router: RouterID,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfLinkStateUpdatePacket {
    pub lsas: Vec<Lsa>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfLinkStateAckPacket {
    pub lsas: Vec<Lsa>, // with LsaKind::NoContent
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsa {
    pub ls_age: u16,
    pub options: OspfOptions,
    pub ls_typ: LsType,
    pub link_state_id: u32,
    pub advertising_router: u32,
    pub ls_seq_no: u32,
    // checksum: u16
    // length: u16 including 20 byte header
    pub content: LsaKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaKind {
    RouterLsa(RouterLsa),
    NetworkLsa(NetworkLsa),
    SummaryLsa(SummaryLsa),
    AsExternalLsa(AsExternalLsa),
    NoConten(),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsType {
    RouterLsa = 1,
    NetworkLsa = 2,
    SummaryIpLsa = 3,
    SummaryAsbrLsa = 4,
    AsExternalLsa = 5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsa {
    pub flags: RouterLsaFlags,
    pub links: Vec<RouterLsaLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaFlags {
    pub virtual_link_endpoint: bool,
    pub external_boundary_router: bool,
    pub area_border_router: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterLsaLink {
    pub id: u32,
    pub data: [u8; 4],
    pub typ: RouterLsaLinkType,
    pub tos: u8,
    pub metric: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterLsaLinkType {
    PointToPoint = 1,
    ConnectToTransitNetwork = 2,
    ConnectToStubNetwork = 3,
    Virtual = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLsa {
    pub netmask: Ipv4Addr,
    pub attached_routers: Vec<RouterID>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryLsa {
    pub netmask: Ipv4Addr,
    pub metric: u32, // actually u24
    pub tos: u8,
    pub tos_metric: u32, // actually u24
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsExternalLsa {
    pub netmask: Ipv4Addr,
    pub metric: u32, // u24,
    pub fwd_addr: Ipv4Addr,
    pub external_route_tag: u32,
    pub tos: u8,
    pub tos_metric: u32, // u24
}

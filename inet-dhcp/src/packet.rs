use std::{
    io::{self, Error, ErrorKind, Read, Write},
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
};

use bitflags::bitflags;
use bytes_io::{BE, BytesReader, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};
use des::prelude::MessageKind;
use inet::types::iface::MacAddress;
use macros::repr_enum;

pub const MESSAGE_KIND_DHCP: MessageKind = 0x63_82;

pub const DHCP_COOKIE: u32 = 0x63825363;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpPacket {
    pub operation: DhcpOp,
    pub htype: u8, // hardware type (e.g. ethernet) - ARP
    pub hlen: u8,  // hardware address len - ARP
    pub hops: u8,  // hardware options - ARP

    pub xid: u32, // transaction id (client choosen)

    pub secs: u16,        // secs since address aquisition started (client set)
    pub flags: DhcpFlags, // flags

    pub ciaddr: Ipv4Addr,   // client ip addr, only at BOUND, RENEW, REBIND
    pub yiaddr: Ipv4Addr,   // ip addr for client
    pub siaddr: Ipv4Addr,   // ip addr of next server in bootstrap
    pub giaddr: Ipv4Addr,   // relay ip addr
    pub chaddr: MacAddress, // client hardware address

    pub sname: String,
    pub file: String,
    pub options: DhcpOptions,
}

repr_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DhcpOp {
        type Repr = u8 where BE;

        BootRequest = 1,
        BootReply = 2,
        Wakeup = 3,
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DhcpFlags: u16 {
        const BROADCAST = 0b1000_0000_0000_0000;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct DhcpOptions(Vec<DhcpOption>);

impl Deref for DhcpOptions {
    type Target = Vec<DhcpOption>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for DhcpOptions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Into<Vec<DhcpOption>>> From<T> for DhcpOptions {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

pub const OPT_CODE_PAD: u8 = 0;
pub const OPT_CODE_SUBNET_MASK: u8 = 1;
pub const OPT_CODE_TIME_OFFSET: u8 = 2;
pub const OPT_CODE_ROUTER: u8 = 3;
pub const OPT_CODE_TIME_SERVER: u8 = 4;
pub const OPT_CODE_NAME_SEVER: u8 = 5;
pub const OPT_CODE_DOMAIN_NAME_SEVER: u8 = 6;
pub const OPT_CODE_LOG_SEVER: u8 = 7;
pub const OPT_CODE_COOKIE_SEVER: u8 = 8;
pub const OPT_CODE_LPR_SEVER: u8 = 9;
pub const OPT_CODE_IMPRESS_SEVER: u8 = 10;
pub const OPT_CODE_RESOURCE_LOCATION_SEVER: u8 = 11;
pub const OPT_CODE_HOST_NAME: u8 = 12;
pub const OPT_CODE_BOOT_FILE_SIZE: u8 = 13;
pub const OPT_CODE_METRIT_DUMP_FILE: u8 = 14;
pub const OPT_CODE_DOMAIN_NAME: u8 = 15;
pub const OPT_CODE_SWAP_SERVER: u8 = 16;
pub const OPT_CODE_ROOT_PATH: u8 = 17;
pub const OPT_CODE_EXTENSION_PATH: u8 = 18;
pub const OPT_CODE_IP_FWD: u8 = 19;
pub const OPT_CODE_NON_LOCAL_SRC_ROUTING: u8 = 20;
pub const OPT_CODE_POLICY_FILTER: u8 = 21;
pub const OPT_CODE_MAX_REASSEMBLY_SIZE: u8 = 22;
pub const OPT_CODE_IP_DEFAULT_TTL: u8 = 23;
pub const OPT_CODE_PATH_MTU_AGING: u8 = 24;
pub const OPT_CODE_PATH_MTU_PLATEAU: u8 = 25;
pub const OPT_CODE_INTERFACE_MTU: u8 = 26;
pub const OPT_CODE_ALL_SUBNETS_LOCAL: u8 = 27;
pub const OPT_CODE_BROADCAST_ADDR: u8 = 28;
pub const OPT_CODE_PERFORM_MASK_DISCOVERY: u8 = 29;
pub const OPT_CODE_MASK_SUPPLIER: u8 = 30;
pub const OPT_CODE_PERFORM_ROUTER_DISCOVERY: u8 = 31;
pub const OPT_CODE_ROUTER_SOLICITATION_ADDR: u8 = 32;
pub const OPT_CODE_STATIC_ROUTE: u8 = 33;
pub const OPT_CODE_TRAILER_ENCAPSULATION: u8 = 34;
pub const OPT_CODE_ARP_CACHE_TIMEOUT: u8 = 35;
pub const OPT_CODE_ETHERNET_ENCAPSULATION: u8 = 36;
pub const OPT_CODE_TCP_TTL: u8 = 37;
pub const OPT_CODE_TCP_KEEPALIVE_INTERVAL: u8 = 38;
pub const OPT_CODE_TCP_KEEPALIVE_GARBAGE: u8 = 39;
pub const OPT_CODE_NETWORK_INFORMATION_SERVICE_DOMAIN: u8 = 40;
pub const OPT_CODE_NETWORK_INFORMATION_SERVERS: u8 = 41;
pub const OPT_CODE_NETWORK_TIME_PROTOCOL_SERVERS: u8 = 42;
/* Vendor specific */
pub const OPT_CODE_DHCP_REQUESTED_ADDR: u8 = 50;
pub const OPT_CODE_DHCP_IP_ADDR_LEASE: u8 = 51;
pub const OPT_CODE_DHCP_OPTION_OVERLOAD: u8 = 52;
pub const OPT_CODE_DHCP_MESSAGE_TYPE: u8 = 53;
pub const OPT_CODE_DHCP_SERVER_IDENTIFIER: u8 = 54;
pub const OPT_CODE_DHCP_PARAM_REQ_LIST: u8 = 55;
pub const OPT_CODE_DHCP_MESSAGE: u8 = 56;
pub const OPT_CODE_DHCP_MAX_MESSAGE_SIZE: u8 = 57;
pub const OPT_CODE_DHCP_RENEWAL_TIME: u8 = 58;
pub const OPT_CODE_DHCP_REBIND_TIME: u8 = 59;
pub const OPT_CODE_DHCP_CLASS_IDENTIFIER: u8 = 60;
pub const OPT_CODE_DHCP_CLIENT_IDENTIFIER: u8 = 61;
pub const OPT_CODE_END: u8 = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    TimeOffset(u32),
    Routers(Vec<Ipv4Addr>),
    TimeServers(Vec<Ipv4Addr>),
    NameServers(Vec<Ipv4Addr>),
    DomainNameServers(Vec<Ipv4Addr>),
    LogServers(Vec<Ipv4Addr>),
    CookieServers(Vec<Ipv4Addr>),
    LRPServers(Vec<Ipv4Addr>),
    ImpressServers(Vec<Ipv4Addr>),
    ResourceLocationServers(Vec<Ipv4Addr>),
    HostName(String),
    BootFileSize(u16),
    MeritDumpFile(String),
    DomainName(String),
    SwapServer(String),
    RootPath(String),
    ExtensionPath(String),
    IpForward(bool),
    IpNonLocalSourceRouting(bool),
    PolicyFilter(Vec<Ipv4Addr>),
    MaximumReassamblySize(u16),
    IpDefaultTTL(u8),
    PathMtuAging(u32),
    PathMtuPlateau(Vec<u16>),
    InterfaceMTU(u16),
    AllSubnetsLocal(bool),
    BroadcastAddr(Ipv4Addr),
    PerformMaskDiscovery(bool),
    MaskSupplier(bool),
    PerformRouterDiscovery(bool),
    RouterSolicititationAddr(Ipv4Addr),
    StaticRoutes(Vec<Ipv4Addr>),
    TrailerEncapsulation(bool),
    ArpCacheTimeout(u32),
    EthernetEncapsulation(bool),
    TcpDefaultTTL(u8),
    TcpKeepaliveInterval(u32),
    TcpKeepaliveGarbarge(bool),
    NetworkInformationServiceDomain(String),
    NetworkInformationServers(Vec<Ipv4Addr>),
    NetworkTimeProtocolServers(Vec<Ipv4Addr>),
    RequestedIpAddr(Ipv4Addr),
    IpAddrLeaseTime(u32),
    OptionOverload(u8), // 0,1,2
    MessageType(DhcpMessageType),
    ServerIdentifier(Ipv4Addr),
    ParameterRequestList(Vec<u8>),
    Message(String),
    MaximumDhcpSize(u16),
    RenewalTime(u32),
    RebindingTime(u32),
    ClassIdentifier(String),
    ClientIdentifier(String),
}

repr_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DhcpMessageType {
        type Repr = u8 where BE;

        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nack = 6,
        Release = 7,
    }
}

impl ToBytes for DhcpPacket {
    type Error = std::io::Error;
    fn to_bytes(&self, writer: &mut bytes_io::BytesWriter) -> Result<(), Self::Error> {
        writer.write_u8(self.operation.to_raw_repr())?;
        writer.write_u8(self.htype)?;
        writer.write_u8(self.hlen)?;
        writer.write_u8(self.hops)?;

        writer.write_u32::<BE>(self.xid)?;
        writer.write_u16::<BE>(self.secs)?;
        writer.write_u16::<BE>(self.flags.bits())?;

        self.ciaddr.to_bytes(writer)?;
        self.yiaddr.to_bytes(writer)?;
        self.siaddr.to_bytes(writer)?;
        self.giaddr.to_bytes(writer)?;

        writer.write_all(self.chaddr.as_slice())?;
        writer.write_all(&[0; 10])?;

        writer.write_all(&efixed::<64>(self.sname.as_bytes())?)?;
        writer.write_all(&efixed::<128>(self.file.as_bytes())?)?;

        writer.write_u32::<BE>(DHCP_COOKIE)?;

        self.options.to_bytes(writer)?;

        Ok(())
    }
}

impl ToBytes for DhcpOptions {
    type Error = std::io::Error;
    fn to_bytes(&self, writer: &mut bytes_io::BytesWriter) -> Result<(), Self::Error> {
        let marker = writer.marker::<()>();
        for option in &self.0 {
            option.to_bytes(writer)?;
        }
        writer.write_u8(OPT_CODE_END)?;
        let len = writer.bytes_written_since(&marker) % 4;
        writer.apply(marker); // < so that we dont panic
        writer.put_bytes(OPT_CODE_PAD, len);

        Ok(())
    }
}

impl ToBytes for DhcpOption {
    type Error = std::io::Error;
    fn to_bytes(&self, w: &mut bytes_io::BytesWriter) -> Result<(), Self::Error> {
        use DhcpOption::*;
        match self {
            SubnetMask(addr) => enc(w, OPT_CODE_SUBNET_MASK, |w| addr.to_bytes(w)),
            TimeOffset(offset) => enc(w, OPT_CODE_TIME_OFFSET, |w| w.write_u32::<BE>(*offset)),
            Routers(addrs) => enc(w, OPT_CODE_ROUTER, |w| emany(w, addrs)),
            TimeServers(addrs) => enc(w, OPT_CODE_TIME_SERVER, |w| emany(w, addrs)),
            NameServers(addrs) => enc(w, OPT_CODE_NAME_SEVER, |w| emany(w, addrs)),
            DomainNameServers(addrs) => enc(w, OPT_CODE_DOMAIN_NAME_SEVER, |w| emany(w, addrs)),
            LogServers(addrs) => enc(w, OPT_CODE_LOG_SEVER, |w| emany(w, addrs)),
            CookieServers(addrs) => enc(w, OPT_CODE_COOKIE_SEVER, |w| emany(w, addrs)),
            LRPServers(addrs) => enc(w, OPT_CODE_LPR_SEVER, |w| emany(w, addrs)),
            ImpressServers(addrs) => enc(w, OPT_CODE_IMPRESS_SEVER, |w| emany(w, addrs)),
            ResourceLocationServers(addrs) => {
                enc(w, OPT_CODE_RESOURCE_LOCATION_SEVER, |w| emany(w, addrs))
            }
            HostName(name) => enc(w, OPT_CODE_HOST_NAME, |w| w.write_all(name.as_bytes())),
            BootFileSize(size) => enc(w, OPT_CODE_BOOT_FILE_SIZE, |w| w.write_u16::<BE>(*size)),
            MeritDumpFile(name) => enc(w, OPT_CODE_METRIT_DUMP_FILE, |w| {
                w.write_all(name.as_bytes())
            }),
            DomainName(name) => enc(w, OPT_CODE_DOMAIN_NAME, |w| w.write_all(name.as_bytes())),
            SwapServer(name) => enc(w, OPT_CODE_SWAP_SERVER, |w| w.write_all(name.as_bytes())),
            RootPath(name) => enc(w, OPT_CODE_ROOT_PATH, |w| w.write_all(name.as_bytes())),
            ExtensionPath(name) => {
                enc(w, OPT_CODE_EXTENSION_PATH, |w| w.write_all(name.as_bytes()))
            }
            IpForward(b) => enc(w, OPT_CODE_IP_FWD, |w| w.write_u8(*b as u8)),
            IpNonLocalSourceRouting(b) => {
                enc(w, OPT_CODE_NON_LOCAL_SRC_ROUTING, |w| w.write_u8(*b as u8))
            }
            PolicyFilter(addrs) => enc(w, OPT_CODE_POLICY_FILTER, |w| emany(w, addrs)),
            MaximumReassamblySize(size) => enc(w, OPT_CODE_MAX_REASSEMBLY_SIZE, |w| {
                w.write_u16::<BE>(*size)
            }),
            IpDefaultTTL(size) => enc(w, OPT_CODE_IP_DEFAULT_TTL, |w| w.write_u8(*size)),
            PathMtuAging(par) => enc(w, OPT_CODE_PATH_MTU_AGING, |w| w.write_u32::<BE>(*par)),
            PathMtuPlateau(pars) => enc(w, OPT_CODE_PATH_MTU_PLATEAU, |w| emany(w, pars)),
            InterfaceMTU(size) => enc(w, OPT_CODE_INTERFACE_MTU, |w| w.write_u16::<BE>(*size)),
            AllSubnetsLocal(b) => enc(w, OPT_CODE_ALL_SUBNETS_LOCAL, |w| w.write_u8(*b as u8)),
            BroadcastAddr(addr) => enc(w, OPT_CODE_BROADCAST_ADDR, |w| addr.to_bytes(w)),
            PerformMaskDiscovery(b) => {
                enc(w, OPT_CODE_PERFORM_MASK_DISCOVERY, |w| w.write_u8(*b as u8))
            }
            MaskSupplier(b) => enc(w, OPT_CODE_MASK_SUPPLIER, |w| w.write_u8(*b as u8)),
            PerformRouterDiscovery(b) => enc(w, OPT_CODE_PERFORM_ROUTER_DISCOVERY, |w| {
                w.write_u8(*b as u8)
            }),
            RouterSolicititationAddr(addr) => {
                enc(w, OPT_CODE_ROUTER_SOLICITATION_ADDR, |w| addr.to_bytes(w))
            }
            StaticRoutes(addrs) => enc(w, OPT_CODE_STATIC_ROUTE, |w| emany(w, addrs)),
            TrailerEncapsulation(b) => {
                enc(w, OPT_CODE_TRAILER_ENCAPSULATION, |w| w.write_u8(*b as u8))
            }
            ArpCacheTimeout(par) => enc(w, OPT_CODE_ARP_CACHE_TIMEOUT, |w| w.write_u32::<BE>(*par)),
            EthernetEncapsulation(b) => {
                enc(w, OPT_CODE_ETHERNET_ENCAPSULATION, |w| w.write_u8(*b as u8))
            }
            TcpDefaultTTL(size) => enc(w, OPT_CODE_TCP_TTL, |w| w.write_u8(*size)),
            TcpKeepaliveInterval(par) => enc(w, OPT_CODE_TCP_KEEPALIVE_INTERVAL, |w| {
                w.write_u32::<BE>(*par)
            }),
            TcpKeepaliveGarbarge(b) => {
                enc(w, OPT_CODE_TCP_KEEPALIVE_GARBAGE, |w| w.write_u8(*b as u8))
            }
            NetworkInformationServiceDomain(domain) => {
                enc(w, OPT_CODE_NETWORK_INFORMATION_SERVICE_DOMAIN, |w| {
                    w.write_all(domain.as_bytes())
                })
            }
            NetworkInformationServers(addrs) => {
                enc(w, OPT_CODE_NETWORK_INFORMATION_SERVERS, |w| emany(w, addrs))
            }
            NetworkTimeProtocolServers(addrs) => {
                enc(w, OPT_CODE_NETWORK_TIME_PROTOCOL_SERVERS, |w| {
                    emany(w, addrs)
                })
            }
            RequestedIpAddr(addr) => enc(w, OPT_CODE_DHCP_REQUESTED_ADDR, |w| addr.to_bytes(w)),
            IpAddrLeaseTime(par) => {
                enc(w, OPT_CODE_DHCP_IP_ADDR_LEASE, |w| w.write_u32::<BE>(*par))
            }
            OptionOverload(par) => enc(w, OPT_CODE_DHCP_OPTION_OVERLOAD, |w| w.write_u8(*par)),
            MessageType(typ) => enc(w, OPT_CODE_DHCP_MESSAGE_TYPE, |w| {
                w.write_u8(typ.to_raw_repr())
            }),
            ServerIdentifier(addr) => enc(w, OPT_CODE_DHCP_SERVER_IDENTIFIER, |w| addr.to_bytes(w)),
            ParameterRequestList(list) => enc(w, OPT_CODE_DHCP_PARAM_REQ_LIST, |w| emany(w, list)),
            Message(name) => enc(w, OPT_CODE_DHCP_MESSAGE, |w| w.write_all(name.as_bytes())),
            MaximumDhcpSize(size) => enc(w, OPT_CODE_DHCP_MAX_MESSAGE_SIZE, |w| {
                w.write_u16::<BE>(*size)
            }),
            RenewalTime(size) => enc(w, OPT_CODE_DHCP_RENEWAL_TIME, |w| w.write_u32::<BE>(*size)),
            RebindingTime(size) => enc(w, OPT_CODE_DHCP_REBIND_TIME, |w| w.write_u32::<BE>(*size)),
            ClassIdentifier(name) => enc(w, OPT_CODE_DHCP_CLASS_IDENTIFIER, |w| {
                w.write_all(name.as_bytes())
            }),
            ClientIdentifier(name) => enc(w, OPT_CODE_DHCP_CLIENT_IDENTIFIER, |w| {
                w.write_all(name.as_bytes())
            }),
        }
    }
}

fn efixed<const N: usize>(bytes: &[u8]) -> io::Result<[u8; N]> {
    let mut buf = [0; N];
    (&mut buf[..]).write_all(bytes)?;
    Ok(buf)
}

fn enc(
    writer: &mut bytes_io::BytesWriter,
    code: u8,
    f: impl FnOnce(&mut bytes_io::BytesWriter) -> std::io::Result<()>,
) -> std::io::Result<()> {
    writer.write_u8(code)?;
    let marker = writer.marker::<u8>();
    f(writer)?;
    let len = writer.bytes_written_since(&marker) as u8;
    writer.apply(marker).write_u8(len)?;
    Ok(())
}

fn emany<T: ToBytes<Error = std::io::Error>>(
    writer: &mut bytes_io::BytesWriter,
    addrs: &Vec<T>,
) -> std::io::Result<()> {
    for addr in addrs {
        addr.to_bytes(writer)?;
    }
    Ok(())
}

impl FromBytes for DhcpPacket {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let operation = DhcpOp::from_raw_repr(stream.read_u8()?)?;
        let htype = stream.read_u8()?;
        let hlen = stream.read_u8()?;
        let hops = stream.read_u8()?;

        let xid = stream.read_u32::<BE>()?;
        let secs = stream.read_u16::<BE>()?;
        let flags = DhcpFlags::from_bits_truncate(stream.read_u16::<BE>()?);

        let ciaddr = Ipv4Addr::from_bytes(stream)?;
        let yiaddr = Ipv4Addr::from_bytes(stream)?;
        let siaddr = Ipv4Addr::from_bytes(stream)?;
        let giaddr = Ipv4Addr::from_bytes(stream)?;

        let mut buf = [0; 16];
        stream.read_exact(&mut buf)?;
        let chaddr = MacAddress::peek_from(&buf[..6])?;

        let sname = rcstr::<64>(stream)?;
        let file = rcstr::<128>(stream)?;

        let cookie = stream.read_u32::<BE>()?;
        if cookie != DHCP_COOKIE {
            return Err(Error::new(ErrorKind::InvalidData, "invalid cookie"));
        }

        let options = DhcpOptions::from_bytes(stream)?;

        Ok(DhcpPacket {
            operation,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }
}

fn rcstr<const N: usize>(r: &mut BytesReader) -> io::Result<String> {
    let mut buf = [0; N];
    r.read_exact(&mut buf)?;
    let n = buf.iter().position(|v| *v == 0).unwrap_or(N);
    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

impl FromBytes for DhcpOptions {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut options = Vec::new();
        loop {
            let code = stream.peek().read_u8()?;
            if code == OPT_CODE_END {
                break;
            }
            options.push(DhcpOption::from_bytes(stream)?);
        }

        let _ = stream.read_u8()?;
        while stream.has_remaining() {
            let pad = stream.read_u8()?;
            if pad != OPT_CODE_PAD {
                return Err(Error::new(ErrorKind::InvalidData, "invalid pad"));
            }
        }

        Ok(Self(options))
    }
}

impl FromBytes for DhcpOption {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut bytes_io::BytesReader) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        use DhcpOption::*;

        let code = stream.read_u8()?;
        let len = stream.read_u8()?;
        stream.extract(len as usize, |stream| match code {
            OPT_CODE_SUBNET_MASK => Ipv4Addr::from_bytes(stream).map(SubnetMask),
            OPT_CODE_TIME_OFFSET => stream.read_u32::<BE>().map(TimeOffset),
            OPT_CODE_ROUTER => rmany(stream).map(Routers),
            OPT_CODE_TIME_SERVER => rmany(stream).map(TimeServers),
            OPT_CODE_NAME_SEVER => rmany(stream).map(NameServers),
            OPT_CODE_DOMAIN_NAME_SEVER => rmany(stream).map(DomainNameServers),
            OPT_CODE_LOG_SEVER => rmany(stream).map(LogServers),
            OPT_CODE_COOKIE_SEVER => rmany(stream).map(CookieServers),
            OPT_CODE_LPR_SEVER => rmany(stream).map(LRPServers),
            OPT_CODE_IMPRESS_SEVER => rmany(stream).map(ImpressServers),
            OPT_CODE_RESOURCE_LOCATION_SEVER => rmany(stream).map(ResourceLocationServers),
            OPT_CODE_HOST_NAME => rstring(stream).map(HostName),
            OPT_CODE_BOOT_FILE_SIZE => stream.read_u16::<BE>().map(BootFileSize),
            OPT_CODE_METRIT_DUMP_FILE => rstring(stream).map(MeritDumpFile),
            OPT_CODE_DOMAIN_NAME => rstring(stream).map(DomainName),
            OPT_CODE_SWAP_SERVER => rstring(stream).map(SwapServer),
            OPT_CODE_ROOT_PATH => rstring(stream).map(RootPath),
            OPT_CODE_EXTENSION_PATH => rstring(stream).map(ExtensionPath),
            OPT_CODE_IP_FWD => rbool(stream).map(IpForward),
            OPT_CODE_NON_LOCAL_SRC_ROUTING => rbool(stream).map(IpNonLocalSourceRouting),
            OPT_CODE_POLICY_FILTER => rmany(stream).map(PolicyFilter),
            OPT_CODE_MAX_REASSEMBLY_SIZE => stream.read_u16::<BE>().map(MaximumReassamblySize),
            OPT_CODE_IP_DEFAULT_TTL => stream.read_u8().map(IpDefaultTTL),
            OPT_CODE_PATH_MTU_AGING => stream.read_u32::<BE>().map(PathMtuAging),
            OPT_CODE_PATH_MTU_PLATEAU => rmany(stream).map(PathMtuPlateau),
            OPT_CODE_INTERFACE_MTU => stream.read_u16::<BE>().map(InterfaceMTU),
            OPT_CODE_ALL_SUBNETS_LOCAL => rbool(stream).map(AllSubnetsLocal),
            OPT_CODE_BROADCAST_ADDR => Ipv4Addr::from_bytes(stream).map(BroadcastAddr),
            OPT_CODE_PERFORM_MASK_DISCOVERY => rbool(stream).map(PerformMaskDiscovery),
            OPT_CODE_MASK_SUPPLIER => rbool(stream).map(MaskSupplier),
            OPT_CODE_PERFORM_ROUTER_DISCOVERY => rbool(stream).map(PerformRouterDiscovery),
            OPT_CODE_ROUTER_SOLICITATION_ADDR => {
                Ipv4Addr::from_bytes(stream).map(RouterSolicititationAddr)
            }
            OPT_CODE_STATIC_ROUTE => rmany(stream).map(StaticRoutes),
            OPT_CODE_TRAILER_ENCAPSULATION => rbool(stream).map(TrailerEncapsulation),
            OPT_CODE_ARP_CACHE_TIMEOUT => stream.read_u32::<BE>().map(ArpCacheTimeout),
            OPT_CODE_ETHERNET_ENCAPSULATION => rbool(stream).map(EthernetEncapsulation),
            OPT_CODE_TCP_TTL => stream.read_u8().map(TcpDefaultTTL),
            OPT_CODE_TCP_KEEPALIVE_INTERVAL => stream.read_u32::<BE>().map(TcpKeepaliveInterval),
            OPT_CODE_TCP_KEEPALIVE_GARBAGE => rbool(stream).map(TcpKeepaliveGarbarge),
            OPT_CODE_NETWORK_INFORMATION_SERVICE_DOMAIN => {
                rstring(stream).map(NetworkInformationServiceDomain)
            }
            OPT_CODE_NETWORK_INFORMATION_SERVERS => rmany(stream).map(NetworkInformationServers),
            OPT_CODE_NETWORK_TIME_PROTOCOL_SERVERS => rmany(stream).map(NetworkTimeProtocolServers),
            /* Vendor specific */
            OPT_CODE_DHCP_REQUESTED_ADDR => Ipv4Addr::from_bytes(stream).map(RequestedIpAddr),
            OPT_CODE_DHCP_IP_ADDR_LEASE => stream.read_u32::<BE>().map(IpAddrLeaseTime),
            OPT_CODE_DHCP_OPTION_OVERLOAD => stream.read_u8().map(OptionOverload),
            OPT_CODE_DHCP_MESSAGE_TYPE => stream
                .read_u8()
                .and_then(DhcpMessageType::from_raw_repr)
                .map(MessageType),
            OPT_CODE_DHCP_SERVER_IDENTIFIER => Ipv4Addr::from_bytes(stream).map(ServerIdentifier),
            OPT_CODE_DHCP_PARAM_REQ_LIST => rmany(stream).map(ParameterRequestList),
            OPT_CODE_DHCP_MESSAGE => rstring(stream).map(Message),
            OPT_CODE_DHCP_MAX_MESSAGE_SIZE => stream.read_u16::<BE>().map(MaximumDhcpSize),
            OPT_CODE_DHCP_RENEWAL_TIME => stream.read_u32::<BE>().map(RenewalTime),
            OPT_CODE_DHCP_REBIND_TIME => stream.read_u32::<BE>().map(RebindingTime),
            OPT_CODE_DHCP_CLASS_IDENTIFIER => rstring(stream).map(ClassIdentifier),
            OPT_CODE_DHCP_CLIENT_IDENTIFIER => rstring(stream).map(ClientIdentifier),
            _ => Err(Error::new(ErrorKind::InvalidData, "invalid code")),
        })
    }
}

#[inline]
fn rmany<T: FromBytes>(stream: &mut BytesReader<'_>) -> Result<Vec<T>, T::Error> {
    let mut items = Vec::new();
    while stream.has_remaining() {
        items.push(T::from_bytes(stream)?);
    }
    Ok(items)
}

#[inline]
fn rstring(stream: &mut BytesReader<'_>) -> io::Result<String> {
    let mut str = String::new();
    stream.read_to_string(&mut str)?;
    Ok(str)
}

#[inline]
fn rbool(stream: &mut BytesReader<'_>) -> io::Result<bool> {
    stream.read_u8().map(|v| v > 0)
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use bytes_io::assert_encoding_e2e;
    use rand::random;

    use super::*;

    fn gmany<T>(f: impl FnMut() -> T) -> Vec<T> {
        gmanyn(10, f)
    }

    fn gmanyn<T>(n: usize, f: impl FnMut() -> T) -> Vec<T> {
        let n = random::<u64>() as usize % n;
        repeat_with(f).take(n).collect()
    }

    fn gstring() -> String {
        String::from_utf8_lossy(&gmanyn(30, || 64 + random::<u8>() % 26)).to_string()
    }

    fn gmaybe<T>(f: impl FnOnce() -> T) -> Option<T> {
        let seed = random::<u8>();
        if seed < 80 { Some(f()) } else { None }
    }

    impl DhcpPacket {
        fn random() -> Self {
            Self {
                operation: DhcpOp::random(),
                hlen: random(),
                htype: random(),
                hops: random(),
                xid: random(),
                secs: random(),
                flags: DhcpFlags::from_bits_truncate(random()),
                ciaddr: random::<u32>().into(),
                yiaddr: random::<u32>().into(),
                siaddr: random::<u32>().into(),
                giaddr: random::<u32>().into(),
                chaddr: MacAddress::from(random::<[u8; 6]>()),
                sname: gmaybe(gstring).unwrap_or(String::new()),
                file: gmaybe(gstring).unwrap_or(String::new()),
                options: DhcpOptions::random(),
            }
        }
    }

    impl DhcpOp {
        fn random() -> Self {
            let raw = 1 + (random::<u8>() % 3);
            DhcpOp::from_raw_repr(raw).unwrap()
        }
    }

    impl DhcpOptions {
        fn random() -> Self {
            Self(gmany(DhcpOption::random))
        }
    }

    impl DhcpOption {
        fn random() -> Self {
            use DhcpOption::*;
            let options = [
                || SubnetMask(random::<u32>().into()),
                || TimeOffset(random::<u32>()),
                || Routers(gmany(|| random::<u32>().into())),
                || TimeServers(gmany(|| random::<u32>().into())),
                || NameServers(gmany(|| random::<u32>().into())),
                || DomainNameServers(gmany(|| random::<u32>().into())),
                || LogServers(gmany(|| random::<u32>().into())),
                || CookieServers(gmany(|| random::<u32>().into())),
                || LRPServers(gmany(|| random::<u32>().into())),
                || ImpressServers(gmany(|| random::<u32>().into())),
                || ResourceLocationServers(gmany(|| random::<u32>().into())),
                || HostName(gstring()),
                || BootFileSize(random()),
                || MeritDumpFile(gstring()),
                || DomainName(gstring()),
                || SwapServer(gstring()),
                || RootPath(gstring()),
                || ExtensionPath(gstring()),
                || IpForward(random()),
                || IpNonLocalSourceRouting(random()),
                || PolicyFilter(gmany(|| random::<u32>().into())),
                || MaximumReassamblySize(random()),
                || IpDefaultTTL(random()),
                || PathMtuAging(random()),
                || PathMtuPlateau(gmany(random)),
                || InterfaceMTU(random()),
                || AllSubnetsLocal(random()),
                || BroadcastAddr(random::<u32>().into()),
                || PerformMaskDiscovery(random()),
                || MaskSupplier(random()),
                || PerformRouterDiscovery(random()),
                || RouterSolicititationAddr(random::<u32>().into()),
                || StaticRoutes(gmany(|| random::<u32>().into())),
                || TrailerEncapsulation(random()),
                || ArpCacheTimeout(random()),
                || EthernetEncapsulation(random()),
                || TcpDefaultTTL(random()),
                || TcpKeepaliveInterval(random()),
                || TcpKeepaliveGarbarge(random()),
                || NetworkInformationServiceDomain(gstring()),
                || NetworkInformationServers(gmany(|| random::<u32>().into())),
                || NetworkTimeProtocolServers(gmany(|| random::<u32>().into())),
                || RequestedIpAddr(random::<u32>().into()),
                || IpAddrLeaseTime(random()),
                || OptionOverload(random()), // 0,1,2
                || MessageType(DhcpMessageType::random()),
                || ServerIdentifier(random::<u32>().into()),
                || ParameterRequestList(gmany(random)),
                || Message(gstring()),
                || MaximumDhcpSize(random()),
                || RenewalTime(random()),
                || RebindingTime(random()),
                || ClassIdentifier(gstring()),
                || ClientIdentifier(gstring()),
            ];
            options[random::<u64>() as usize % options.len()]()
        }
    }

    impl DhcpMessageType {
        fn random() -> Self {
            let raw = 1 + (random::<u8>() % 7);
            DhcpMessageType::from_raw_repr(raw).unwrap()
        }
    }

    #[test]
    fn e2e_encoding() {
        let packets = repeat_with(DhcpPacket::random)
            .take(1000)
            .collect::<Vec<_>>();
        assert_encoding_e2e(&packets);
    }
}

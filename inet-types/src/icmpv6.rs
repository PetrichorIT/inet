use std::{
    io::{self, Read, Write},
    net::Ipv6Addr,
    time::Duration,
};

use bytepack::{raw_enum, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt, BE};

use crate::{iface::MacAddress, ip::Ipv6Prefix};

pub const PROTO_ICMPV6: u8 = 58;

/// An ICMP V6 message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IcmpV6Packet {
    // RFC 4443
    DestinationUnreachable(IcmpV6DestinationUnreachable) = 1,
    PacketToBig(IcmpV6PacketToBig) = 2,
    TimeExceeded(IcmpV6TimeExceeded) = 3,
    ParameterProblem(IcmpV6ParameterProblem) = 4,

    EchoRequest(IcmpV6Echo) = 128,
    EchoReply(IcmpV6Echo) = 129,

    // MDL
    MulticastListenerQuery(IcmpV6MulticastListenerMessage) = 130,
    MulticastListenerReport(IcmpV6MulticastListenerMessage) = 131,
    MulticastListenerDone(IcmpV6MulticastListenerMessage) = 132,

    // NDP
    RouterSolicitation(IcmpV6RouterSolicitation) = 133,
    RouterAdvertisment(IcmpV6RouterAdvertisement) = 134,
    NeighborSolicitation(IcmpV6NeighborSolicitation) = 135,
    NeighborAdvertisment(IcmpV6NeighborAdvertisment) = 136,
    Redirect = 137,
}

impl ToBytestream for IcmpV6Packet {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        macro_rules! ser {
            ($(
                $i:ident = $l:literal
            ),*) => {
            match self {
                $(
                    Self::$i(ref inner) => {{
                        stream.write_u8($l)?;
                        inner.to_bytestream(stream)?;
                    }}
                )*
                _ => todo!()
            }
            };
        }

        ser!(
            DestinationUnreachable = 1,
            PacketToBig = 2,
            TimeExceeded = 3,
            ParameterProblem = 4,
            EchoRequest = 128,
            EchoReply = 129,
            /* MDL */
            MulticastListenerQuery = 130,
            MulticastListenerReport = 131,
            MulticastListenerDone = 132,
            /* NDP */
            RouterSolicitation = 133,
            RouterAdvertisment = 134,
            NeighborSolicitation = 135,
            NeighborAdvertisment = 136
        );

        Ok(())
    }
}

impl FromBytestream for IcmpV6Packet {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        macro_rules! deser {
            ($(
                $i:ident($t:ident) = $l:literal
            ),*) => {{
                let typ = stream.read_u8()?;
                match typ {
                    $(
                        $l => Ok(Self::$i($t::from_bytestream(stream)?)),
                    )*
                    _ => panic!("no deser implemented yet typ : {typ}")
                }
            }};
        }

        deser!(
            DestinationUnreachable(IcmpV6DestinationUnreachable) = 1,
            PacketToBig(IcmpV6PacketToBig) = 2,
            TimeExceeded(IcmpV6TimeExceeded) = 3,
            ParameterProblem(IcmpV6ParameterProblem) = 4,
            EchoRequest(IcmpV6Echo) = 128,
            EchoReply(IcmpV6Echo) = 129,
            /* MDL */
            MulticastListenerQuery(IcmpV6MulticastListenerMessage) = 130,
            MulticastListenerReport(IcmpV6MulticastListenerMessage) = 131,
            MulticastListenerDone(IcmpV6MulticastListenerMessage) = 132,
            /* NDP */
            RouterSolicitation(IcmpV6RouterSolicitation) = 133,
            RouterAdvertisment(IcmpV6RouterAdvertisement) = 134,
            NeighborSolicitation(IcmpV6NeighborSolicitation) = 135,
            NeighborAdvertisment(IcmpV6NeighborAdvertisment) = 136
        )
    }
}

/// An error message indicating that a destintation cannot be reached.
///
/// This ICMP error message SHOULD be generated by a router
/// or the senders IPv6 stack, to indicate that a packet cannot
/// be delivered to its destionation, because of any reason
/// other than congestion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6DestinationUnreachable {
    /// The code specifies the reason, why a the packet could
    /// not be delivered.
    pub code: IcmpV6DestinationUnreachableCode,
    /// The error causing IP packet, possibly truncated to fit into
    /// the ICMPv6 message.
    pub packet: Vec<u8>,
}

impl ToBytestream for IcmpV6DestinationUnreachable {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(self.code as u8)?;
        stream.write_u16::<BE>(0)?; // checksum
        stream.write_u32::<BE>(0)?; // padding
        stream.write_all(&self.packet)?;
        Ok(())
    }
}

impl FromBytestream for IcmpV6DestinationUnreachable {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let code = IcmpV6DestinationUnreachableCode::from_raw_repr(stream.read_u8()?)?;
        assert_eq!(0, stream.read_u16::<BE>()?);
        assert_eq!(0, stream.read_u32::<BE>()?);
        let mut packet = Vec::new();
        stream.read_to_end(&mut packet)?;
        Ok(Self { code, packet })
    }
}

/// An error message indicating that a packet was to big.
///
/// This ICMP error message MUST be send if a router
/// drops a packet, because it's size exceeds the MTU of
/// the outgoing link.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6PacketToBig {
    /// The maximum transfer size of the link, which caused the error message.
    pub mtu: u32,
    /// The error causing IP packet, possibly truncated to fit into
    /// the ICMPv6 message.
    pub packet: Vec<u8>,
}

impl ToBytestream for IcmpV6PacketToBig {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(0)?; // code
        stream.write_u16::<BE>(0)?; // checksum
        stream.write_u32::<BE>(self.mtu)?; // padding
        stream.write_all(&self.packet)?; // packet
        Ok(())
    }
}

impl FromBytestream for IcmpV6PacketToBig {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        assert_eq!(0, stream.read_u8()?); // code
        assert_eq!(0, stream.read_u32::<BE>()?); // checksum
        let mtu = stream.read_u32::<BE>()?;
        let mut packet = Vec::new();
        stream.read_to_end(&mut packet)?;
        Ok(Self { mtu, packet })
    }
}

/// An error message indicating that some timiming requirement was exceeded.
///
/// This ICMP error message MUST be send if a router or a host discards a message
/// because:
/// - its hop limit was exceeded
/// - it was fragmented, and the fragment reassembly time was exceeded
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6TimeExceeded {
    /// A detailed error code indicating which requirement was exceeded.
    pub code: IcmpV6TimeExceededCode,
    /// The error causing IP packet, possibly truncated to fit into
    /// the ICMPv6 message.
    pub packet: Vec<u8>,
}

impl ToBytestream for IcmpV6TimeExceeded {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(self.code as u8)?;
        stream.write_u16::<BE>(0)?; // checksum
        stream.write_u32::<BE>(0)?; // padding
        stream.write_all(&self.packet)?;
        Ok(())
    }
}

impl FromBytestream for IcmpV6TimeExceeded {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let code = IcmpV6TimeExceededCode::from_raw_repr(stream.read_u8()?)?;
        assert_eq!(0, stream.read_u16::<BE>()?);
        assert_eq!(0, stream.read_u32::<BE>()?);
        let mut packet = Vec::new();
        stream.read_to_end(&mut packet)?;
        Ok(Self { code, packet })
    }
}

/// An error message indicating the some part of the IP header could not be processed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6ParameterProblem {
    /// A detailed code specifing the problem.
    pub code: IcmpV6ParameterProblemCode,
    /// Indicates the offset into the packet on which the problem was discovered.
    pub pointer: u32,
    /// The error causing IP packet, possibly truncated to fit into
    /// the ICMPv6 message.
    pub packet: Vec<u8>,
}

impl ToBytestream for IcmpV6ParameterProblem {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(self.code as u8)?;
        stream.write_u16::<BE>(0)?; // checksum
        stream.write_u32::<BE>(self.pointer)?;
        stream.write_all(&self.packet)?;
        Ok(())
    }
}

impl FromBytestream for IcmpV6ParameterProblem {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let code = IcmpV6ParameterProblemCode::from_raw_repr(stream.read_u8()?)?;
        assert_eq!(0, stream.read_u16::<BE>()?);
        let pointer = stream.read_u32::<BE>()?;
        let mut packet = Vec::new();
        stream.read_to_end(&mut packet)?;
        Ok(Self {
            code,
            pointer,
            packet,
        })
    }
}

/// An echo packet used for ICMP v6 echo requests and echo replies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6Echo {
    /// An identifier used to match echo requests to echo replies.
    pub identifier: u16,
    /// A sequence number used when a sending multiple pings.
    pub sequence_no: u16,
    /// Some abitrary data, echoed back in a echo reply
    pub data: Vec<u8>,
}

impl ToBytestream for IcmpV6Echo {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(0)?;
        stream.write_u16::<BE>(0)?; // checksum
        stream.write_u16::<BE>(self.identifier)?;
        stream.write_u16::<BE>(self.sequence_no)?;
        stream.write_all(&self.data)?;
        Ok(())
    }
}

impl FromBytestream for IcmpV6Echo {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        assert_eq!(0, stream.read_u8()?);
        assert_eq!(0, stream.read_u16::<BE>()?); // checksum
        let identifier = stream.read_u16::<BE>()?;
        let sequence_no = stream.read_u16::<BE>()?;
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        Ok(Self {
            identifier,
            sequence_no,
            data,
        })
    }
}

/// A message send by a host to prompt routers into generating router advertisments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6RouterSolicitation {
    /// Allowed options:
    /// - [`SourceLinkLayerAddress`]
    ///
    /// [`SourceLinkLayerAddress`]: IcmpV6NDPOption::SourceLinkLayerAddress
    pub options: Vec<IcmpV6NDPOption>,
}

impl ToBytestream for IcmpV6RouterSolicitation {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(0)?;
        stream.write_u16::<BE>(0)?; // checksum
        stream.write_u32::<BE>(0)?; // adding
        for option in &self.options {
            if !matches!(option, IcmpV6NDPOption::SourceLinkLayerAddress(_)) {}
            option.to_bytestream(stream)?;
        }
        Ok(())
    }
}

impl FromBytestream for IcmpV6RouterSolicitation {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        assert_eq!(0, stream.read_u8()?);
        assert_eq!(0, stream.read_u16::<BE>()?); // checksum
        assert_eq!(0, stream.read_u32::<BE>()?);
        let mut options = Vec::new();
        while !stream.is_empty() {
            options.push(IcmpV6NDPOption::from_bytestream(stream)?);
        }
        Ok(Self { options })
    }
}

/// A message send by routers, to advertise their capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6RouterAdvertisement {
    /// The perferred hop count of the router. The value 0 means
    /// unspecified.
    pub current_hop_limit: u8,
    /// This flag indicates the existence of a DHCPv6 service
    /// in this network for address configuration.
    pub managed: bool,
    /// This flag indicates that other configuration informations
    /// not including addressing is available through a DHCPv6 service.
    ///
    /// This flag may only be set if `managed` is not set, since managed
    /// allready indicates to use DHCPv6 fully. Only this flag indicates
    /// that DHCPv6 should not be used for address configuration, BUT
    /// should be used to assign other information.
    pub other_configuration: bool,
    /// A lifetime of the router in seconds. This value should be limited to 9000.
    /// A value of 0 indicates that this router should never be used as the default
    /// router for any host.
    pub router_lifetime: u16,
    /// The timespan which the router guarantees its reachability after sending a reachability
    /// confirmation, in miliseconds.
    pub reachable_time: u32,
    /// The timespan in which the neighor solicitation should be updated, in milliseconds.
    pub retransmit_time: u32,
    /// Allowed options:
    /// - [`SourceLinkLayerAddress`]
    /// - [`Mtu`]
    /// - [`PrefixInformation`]
    ///
    /// [`SourceLinkLayerAddress`]: IcmpV6NDPOption::SourceLinkLayerAddress
    /// [`Mtu`]: IcmpV6NDPOption::Mtu
    /// [`PrefixInformation`]: IcmpV6NDPOption::PrefixInformation
    pub options: Vec<IcmpV6NDPOption>,
}

impl ToBytestream for IcmpV6RouterAdvertisement {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(0)?; // code
        stream.write_u16::<BE>(0)?; // checksum

        stream.write_u8(self.current_hop_limit)?;
        let mut flag_byte = 0;
        if self.managed {
            flag_byte |= 0b1000_0000;
        }
        if self.other_configuration {
            flag_byte |= 0b0100_0000;
        }
        stream.write_u8(flag_byte)?;
        stream.write_u16::<BE>(self.router_lifetime)?;
        stream.write_u32::<BE>(self.reachable_time)?;
        stream.write_u32::<BE>(self.retransmit_time)?;
        for option in &self.options {
            option.to_bytestream(stream)?;
        }
        Ok(())
    }
}

impl FromBytestream for IcmpV6RouterAdvertisement {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        assert_eq!(0, stream.read_u8()?);
        assert_eq!(0, stream.read_u16::<BE>()?);
        let current_hop_limit = stream.read_u8()?;
        let flag_byte = stream.read_u8()?;
        let router_lifetime = stream.read_u16::<BE>()?;
        let reachable_time = stream.read_u32::<BE>()?;
        let retransmit_time = stream.read_u32::<BE>()?;
        let mut options = Vec::new();
        while !stream.is_empty() {
            options.push(IcmpV6NDPOption::from_bytestream(stream)?);
        }

        Ok(Self {
            current_hop_limit,
            managed: (flag_byte & 0b1000_0000) != 0,
            other_configuration: (flag_byte & 0b0100_0000) != 0,
            router_lifetime,
            reachable_time,
            retransmit_time,
            options,
        })
    }
}

/// A message to request link layer addresses of neighbbors.
///
/// These messages are multicasted in discovery mode, but
/// unicasted in verification mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6NeighborSolicitation {
    /// The IP address of the solicitation target.
    ///
    /// This MUST NOT be a multicast address.
    pub target: Ipv6Addr,
    /// Allowed options:
    /// - [`SourceLinkLayerAddress`]
    ///
    /// [`SourceLinkLayerAddress`]: IcmpV6NDPOption::SourceLinkLayerAddress
    pub options: Vec<IcmpV6NDPOption>,
}

impl ToBytestream for IcmpV6NeighborSolicitation {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(0)?; // code
        stream.write_u16::<BE>(0)?; // checksum
        stream.write_u32::<BE>(0)?;
        stream.write_all(&self.target.octets())?;
        for option in &self.options {
            option.to_bytestream(stream)?;
        }
        Ok(())
    }
}

impl FromBytestream for IcmpV6NeighborSolicitation {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        assert_eq!(0, stream.read_u8()?);
        assert_eq!(0, stream.read_u16::<BE>()?);
        assert_eq!(0, stream.read_u32::<BE>()?);
        let target = Ipv6Addr::from(stream.read_u128::<BE>()?);
        let mut options = Vec::new();
        while !stream.is_empty() {
            options.push(IcmpV6NDPOption::from_bytestream(stream)?);
        }
        Ok(Self { target, options })
    }
}

/// A message establishing a solicitation between two neighbors.
///
/// This message is usually send in response to a solictation request,
/// but it might be send unprovoked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6NeighborAdvertisment {
    /// The target address of the solicitation request (aka. the senders address).
    ///
    /// This MUST NO be a multicast address.
    pub target: Ipv6Addr,
    /// A flag that indicates that the sender is a router.
    pub router: bool,
    /// A flag that indicates that this message was send in response to a
    /// neighbor solicitation.
    pub solicited: bool,
    /// A flag that indicates that this advertisment should override the current
    /// cache entry.
    pub overide: bool,
    /// Allowed options:
    /// - [`TargetLinkLayerAddress`]
    ///
    /// [`TargetLinkLayerAddress`]: IcmpV6NDPOption::TargetLinkLayerAddress
    pub options: Vec<IcmpV6NDPOption>,
}

impl ToBytestream for IcmpV6NeighborAdvertisment {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(0)?; // code
        stream.write_u16::<BE>(0)?; // checksum
        let mut flag_bytes = 0;
        if self.router {
            flag_bytes |= 0b1000_0000;
        }
        if self.solicited {
            flag_bytes |= 0b0100_0000;
        }
        if self.overide {
            flag_bytes |= 0b0010_0000;
        }
        stream.write_all(&[flag_bytes, 0, 0, 0])?;
        stream.write_all(&self.target.octets())?;
        for option in &self.options {
            option.to_bytestream(stream)?;
        }
        Ok(())
    }
}

impl FromBytestream for IcmpV6NeighborAdvertisment {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        assert_eq!(0, stream.read_u8()?);
        assert_eq!(0, stream.read_u16::<BE>()?);
        let flag_byte = stream.read_u8()?;
        for _ in 0..3 {
            assert_eq!(0, stream.read_u8()?);
        }
        let target = Ipv6Addr::from(stream.read_u128::<BE>()?);
        let mut options = Vec::new();
        while !stream.is_empty() {
            options.push(IcmpV6NDPOption::from_bytestream(stream)?);
        }
        Ok(Self {
            target,
            router: (flag_byte & 0b1000_0000) != 0,
            solicited: (flag_byte & 0b0100_0000) != 0,
            overide: (flag_byte & 0b0010_0000) != 0,
            options,
        })
    }
}

raw_enum! {
    /// A detailed reason, why a ICMPv6 DestinationUnreachable message was send.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum IcmpV6DestinationUnreachableCode {
        type Repr = u8 where BigEndian;
        /// This error code indicates, that the packet reached a node, whithout
        /// a forwarding entry present for the packets destination.
        NoRouteToDestination = 0,
        /// This error code indicates, that the packet could not reach its destionation
        /// since the path violated some administrativ policy (i.e. a firewall).
        AdministrativelyProhibited = 1,
        /// This error indicates that the scope of the source address was smaller than the scope of the
        /// target address AND the target address lies truly beyond the scope of the source address.
        ///
        /// For example if the source address is link-local, while the target is global unicast AND
        /// the destination in not reachable in the link-local network segement.
        BeyondScopeOfSourceAddress = 2,
        /// This error is a catch all, for all other reason why a destination may not be reachable.
        /// This may include failure to resolve the destintation IPv6 address to a MAC address or the like.
        AddressUnreachable = 3,
        /// This error SHOULD occure in combination with a transport layer protocol and indicates that the
        /// port requested by the transport layer protocol has no listener, and the protocol does not have
        /// an explicit mechanism to inform the sender about this error. (e.g. UDP)
        PortUnreachable = 4,
        /// This errors indicates that the source address is not valid for the requested operation.
        SourceAddressFailed = 5,
        /// This error indicates that a route seems to exist, but some policy prevents the route from
        /// being used. The difference to `AdministrativelyProhibited` is that this error is created by
        /// nodes rejecting destination which are not themselfs, while `AdministrativelyProhibited` rejects
        /// the receiving of messages for one-selfs network segement.
        RejectRoute = 6,
    }
}

raw_enum! {
    /// A detailed reason, which might cause a ICMP TimeExceeded error.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum IcmpV6TimeExceededCode {
        type Repr = u8 where BigEndian;
        /// This code indicates that the hop limit was exceeded on a router within the path.
        HopLimitExceeded = 0,
        /// This code indicates that the packet was fragmented, and the reassembly time was exceede
        FragmentReassemblyTimeExceeded = 1,
    }
}

raw_enum! {
    /// A reponse code to a ICMP desintation unreachable message.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum IcmpV6ParameterProblemCode {
        type Repr = u8 where BigEndian;
        ErroneousHeader = 0,
        UnrecognizedNextHeader = 1,
        UnrecognizedIpv6Option = 2,
    }
}

/// Optional extensions of messages in the Neighbor discovery protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IcmpV6NDPOption {
    /// The senders link layer address.
    SourceLinkLayerAddress(MacAddress),
    /// The targets link layer address.
    TargetLinkLayerAddress(MacAddress),
    /// Information about provided address prefixes by a router.
    PrefixInformation(IcmpV6PrefixInformation),
    /// Information about eh maximum transfer size of the sender.
    Mtu(IcmpV6MtuOption),
    /// An unknown option,
    Unknown(u8, Vec<u8>),
}

impl ToBytestream for IcmpV6NDPOption {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        macro_rules! ser {
            ($(
                $i:ident = $l:literal ($len:literal)
            ),*) => {
                match self {
                    $(
                        Self::$i(ref inner) => {
                            stream.write_u8($l)?;
                            stream.write_u8($len)?;
                            inner.to_bytestream(stream)?;
                        }
                    )*,
                    _ => todo!()
                }
            };
        }

        ser!(
            SourceLinkLayerAddress = 1(1),
            TargetLinkLayerAddress = 2(1),
            PrefixInformation = 3(4),
            Mtu = 5(1)
        );
        Ok(())
    }
}

impl FromBytestream for IcmpV6NDPOption {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        macro_rules! deser {
            ($($i:ident($t:ident) = $l:literal ($len:literal)),*) => {{
                let typ = stream.read_u8()?;
                let len = stream.read_u8()?;
                match (typ, len) {
                    $(
                        ($l, $len) => Ok(Self::$i($t::from_bytestream(stream)?)),
                    )*
                    _ => {
                        let mut buf = vec![0; len as usize];
                        stream.read_exact(&mut buf)?;
                        Ok(Self::Unknown(typ, buf))
                    }
                }
            }};
        }

        deser!(
            SourceLinkLayerAddress(MacAddress) = 1(1),
            TargetLinkLayerAddress(MacAddress) = 2(1),
            PrefixInformation(IcmpV6PrefixInformation) = 3(4),
            Mtu(IcmpV6MtuOption) = 5(1)
        )
    }
}

/// A option that provides on-link prefix information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6PrefixInformation {
    /// The network part of the address, in bits.
    pub prefix_len: u8,
    /// A flag, whether the prefix may be used for on-link determination.
    /// This flag not being set, indicates nothing, but the lack of information.
    pub on_link: bool,
    /// A flag, whether this prefix may be used for stateless address
    /// autoconfiguration.
    pub autonomous_address_configuration: bool,
    /// The timespan in which the prefix remains valid, in seconds.
    pub valid_lifetime: u32,
    /// The preferred timespan which the host should adopt, in seconds.
    pub preferred_lifetime: u32,
    /// The address prefix.
    pub prefix: Ipv6Addr,
}

impl IcmpV6PrefixInformation {
    pub fn prefix(&self) -> Ipv6Prefix {
        Ipv6Prefix::new(self.prefix, self.prefix_len)
    }
}

impl ToBytestream for IcmpV6PrefixInformation {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(self.prefix_len)?;
        let mut flag_byte = 0;
        if self.on_link {
            flag_byte |= 0b1000_0000;
        }
        if self.autonomous_address_configuration {
            flag_byte |= 0b0100_0000;
        }
        stream.write_u8(flag_byte)?;
        stream.write_u32::<BE>(self.valid_lifetime)?;
        stream.write_u32::<BE>(self.preferred_lifetime)?;
        stream.write_u32::<BE>(0)?; // pad
        stream.write_all(&self.prefix.octets())?;
        Ok(())
    }
}

impl FromBytestream for IcmpV6PrefixInformation {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let prefix_len = stream.read_u8()?;
        let flag_byte = stream.read_u8()?;
        let valid_lifetime = stream.read_u32::<BE>()?;
        let preferred_lifetime = stream.read_u32::<BE>()?;
        assert_eq!(0, stream.read_u32::<BE>()?);
        let prefix = Ipv6Addr::from(stream.read_u128::<BE>()?);
        Ok(Self {
            prefix_len,
            on_link: (0b1000_0000 & flag_byte) != 0,
            autonomous_address_configuration: (0b0100_0000 & flag_byte) != 0,
            valid_lifetime,
            preferred_lifetime,
            prefix,
        })
    }
}

pub struct IcmpV6RedirectHeader {}

/// A option that indicates the senders maximum transfer size.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6MtuOption {
    /// The maximum transfer size in bytes.
    pub mtu: u32,
}

impl ToBytestream for IcmpV6MtuOption {
    type Error = io::Error;
    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(0)?;
        stream.write_u32::<BE>(self.mtu)?;
        Ok(())
    }
}

impl FromBytestream for IcmpV6MtuOption {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        assert_eq!(0, stream.read_u16::<BE>()?);
        Ok(Self {
            mtu: stream.read_u32::<BE>()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcmpV6MulticastListenerMessage {
    pub maximum_response_delay: Duration,
    pub multicast_addr: Ipv6Addr,
}

impl ToBytestream for IcmpV6MulticastListenerMessage {
    type Error = io::Error;

    fn to_bytestream(&self, stream: &mut bytepack::BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u8(0)?;
        stream.write_u16::<BE>(0)?;
        stream.write_u16::<BE>(self.maximum_response_delay.as_millis() as u16)?;
        stream.write_u16::<BE>(0)?;
        stream.write_u128::<BE>(u128::from(self.multicast_addr))
    }
}

impl FromBytestream for IcmpV6MulticastListenerMessage {
    type Error = io::Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        assert_eq!(0, stream.read_u8()?);
        assert_eq!(0, stream.read_u16::<BE>()?);
        let maximum_response_delay = Duration::from_millis(stream.read_u16::<BE>()? as u64);
        assert_eq!(0, stream.read_u16::<BE>()?);
        let multicast_addr = Ipv6Addr::from(stream.read_u128::<BE>()?);
        Ok(Self {
            maximum_response_delay,
            multicast_addr,
        })
    }
}
// # RFC 4861 constants

// ## Router constants

pub const NDP_MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);
pub const NDP_MAX_INITIAL_RTR_ADVERTISEMENTS: usize = 3;
pub const NDP_MAX_FINAL_RTR_ADVERTISEMENTS: usize = 3;
pub const NDP_MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(5);
pub const NDP_MAX_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(1000);
pub const NDP_MAX_RA_DELAY_TIME: Duration = Duration::from_millis(500);

// ## Host constants

pub const NDP_MAX_RTR_SOLICITATION_DELAY: Duration = Duration::from_secs(1);
pub const NDP_RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);
pub const NDP_MAX_RTR_SOLICITATIONS: usize = 3;

// ## Node constants

pub const NDP_MAX_MULTICAST_SOLICIT: usize = 3;
pub const NDP_MAX_UNICAST_SOLICIT: usize = 3;
pub const NDP_MAX_ANYCAST_DELAY_TIME: Duration = Duration::from_secs(3);
pub const NDP_MAX_NEIGHBOR_ADVERTISEMENT: usize = 3;
pub const NDP_REACHABLE_TIME: Duration = Duration::from_millis(30_000);
pub const NDP_RETRANS_TIMER: Duration = Duration::from_millis(1_000);
pub const NDP_DELAY_FIRST_PROBE: Duration = Duration::from_secs(5);
pub const NDP_MIN_RANDOM_FACTOR: f64 = 0.5;
pub const NDP_MAX_RANDOM_FACTOR: f64 = 1.5;

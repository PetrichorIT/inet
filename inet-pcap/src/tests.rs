// use bytepack::ToBytestream;
// use des::net::message::Message;
// use inet::{
//     interface::{Interface, NetworkDevice},
//     libpcap::{PcapCapturePoint, PcapEnvelope, PcapSubscriber},
// };
// use inet_types::{icmpv6::*, ip::IpPacket};
// use inet_types::{iface::MacAddress, ip::Ipv6Packet};
// use std::{
//     fs::File,
//     io::{self, BufWriter},
//     net::{IpAddr, Ipv6Addr},
// };

// use crate::LibPcapDeamon;

// struct TestEmitter {
//     deamon: LibPcapDeamon,
//     addr: IpAddr,
// }

// impl TestEmitter {
//     fn new(name: &str, addr: IpAddr) -> io::Result<Self> {
//         let mut deamon = LibPcapDeamon::new(BufWriter::new(Box::new(File::create(format!(
//             "out/{name}.pcap"
//         ))?)));
//         Ok(Self { deamon, addr })
//     }

//     fn emit_into_ipv6(
//         &mut self,
//         pkt: impl ToBytestream<Error = io::Error>,
//         proto: u8,
//     ) -> io::Result<()> {
//         let IpAddr::V6(addr) = self.addr else {
//             panic!()
//         };

//         let ip = Ipv6Packet {
//             traffic_class: 0,
//             flow_label: 0,
//             next_header: proto,
//             hop_limit: 0,
//             src: addr,
//             dst: addr,
//             content: pkt.to_vec()?,
//         };
//         self.emit(IpPacket::V6(ip))
//     }

//     fn emit(&mut self, pkt: IpPacket) -> io::Result<()> {
//         let msg = match pkt {
//             IpPacket::V4(pkt) => Message::new().kind(0x0800).content(pkt).build(),
//             IpPacket::V6(pkt) => Message::new().kind(0x86DD).content(pkt).build(),
//         };

//         self.deamon.capture(PcapEnvelope {
//             capture: PcapCapturePoint::Ingress,
//             message: &msg,
//             iface: &Interface::eth(NetworkDevice::loopback(), self.addr),
//         })
//     }
// }

// fn sample_ipv6packet() -> Ipv6Packet {
//     Ipv6Packet {
//         traffic_class: 0,
//         flow_label: 0,
//         next_header: 0,
//         hop_limit: 0,
//         src: "aa:bb:cc:dd::".parse().unwrap(),
//         dst: "11:22:33:4::".parse().unwrap(),
//         content: "Hello World!".as_bytes().to_vec(),
//     }
// }

// #[test]
// fn icmp_v6_pcap_generation() -> io::Result<()> {
//     let mut emitter = TestEmitter::new("icmpv6", "fe80::aaaa".parse().unwrap())?;

//     let pkt = IcmpV6Packet::DestinationUnreachable(IcmpV6DestinationUnreachable {
//         code: IcmpV6DestinationUnreachableCode::NoRouteToDestination,
//         packet: sample_ipv6packet().to_vec()?,
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::PacketToBig(IcmpV6PacketToBig {
//         mtu: 1500,
//         packet: sample_ipv6packet().to_vec()?,
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::TimeExceeded(IcmpV6TimeExceeded {
//         code: IcmpV6TimeExceededCode::HopLimitExceeded,
//         packet: sample_ipv6packet().to_vec()?,
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::ParameterProblem(IcmpV6ParameterProblem {
//         code: IcmpV6ParameterProblemCode::UnrecognizedNextHeader,
//         pointer: 4,
//         packet: sample_ipv6packet().to_vec()?,
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::EchoRequest(IcmpV6Echo {
//         identifier: 42,
//         sequence_no: 1,
//         data: "Echo ECHO".as_bytes().to_vec(),
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::EchoReply(IcmpV6Echo {
//         identifier: 42,
//         sequence_no: 1,
//         data: "Echo ECHO".as_bytes().to_vec(),
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::RouterSolicitation(IcmpV6RouterSolicitation {
//         options: vec![IcmpV6NDPOption::SourceLinkLayerAddress(MacAddress::from([
//             1, 2, 3, 4, 5, 6,
//         ]))],
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::RouterAdvertisment(IcmpV6RouterAdvertisement {
//         current_hop_limit: 0,
//         managed: false,
//         other_configuration: false,
//         router_lifetime: u16::MAX,
//         reachable_time: 18_000,
//         retransmit_time: 18_000,
//         options: vec![
//             IcmpV6NDPOption::PrefixInformation(IcmpV6PrefixInformation {
//                 prefix_len: 64,
//                 on_link: false,
//                 autonomous_address_configuration: true,
//                 valid_lifetime: 6_000,
//                 preferred_lifetime: 6_000,
//                 prefix: "2003:ccab:4461::".parse().unwrap(),
//             }),
//             IcmpV6NDPOption::PrefixInformation(IcmpV6PrefixInformation {
//                 prefix_len: 48,
//                 on_link: false,
//                 autonomous_address_configuration: true,
//                 valid_lifetime: 6_000,
//                 preferred_lifetime: 6_000,
//                 prefix: "2003:ccab:cccc::".parse().unwrap(),
//             }),
//         ],
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::NeighborSolicitation(IcmpV6NeighborSolicitation {
//         target: Ipv6Addr::from(0x010203040560708),
//         options: vec![
//             IcmpV6NDPOption::SourceLinkLayerAddress(MacAddress::from([1, 2, 3, 4, 5, 6])),
//             IcmpV6NDPOption::TargetLinkLayerAddress(MacAddress::from([1, 2, 3, 4, 5, 6])),
//         ],
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     let pkt = IcmpV6Packet::NeighborAdvertisment(IcmpV6NeighborAdvertisment {
//         target: Ipv6Addr::from(0x010203040560708),
//         router: false,
//         solicited: false,
//         overide: false,
//         options: vec![IcmpV6NDPOption::TargetLinkLayerAddress(MacAddress::from([
//             6, 5, 4, 3, 2, 1,
//         ]))],
//     });
//     emitter.emit_into_ipv6(pkt, 58)?;

//     Ok(())
// }

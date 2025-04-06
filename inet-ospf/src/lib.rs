pub mod packet;

#[cfg(test)]
mod tests {
    // use std::{fs::File, net::Ipv4Addr};

    // use bytes_io::ToBytes;
    // use inet::types::ip::{Ipv4Flags, Ipv4Packet, KIND_IPV4};
    // use pcapng::{BlockWriter, DefaultBlockWriter, Linktype};

    // use crate::packet::{OspfPacket, PROTO_OSPF};

    // #[test]
    // fn pcap_gen() {
    //     let mut writer =
    //         DefaultBlockWriter::<_, ()>::new(File::create("inet-ospf-out.pcapng").unwrap(), "ospf")
    //             .unwrap();
    //     writer
    //         .add_interface(&(), Linktype::ETHERNET, 4096, Vec::new())
    //         .unwrap();

    //     for i in 0..100 {
    //         let ospf = OspfPacket::random();
    //         dbg!(&ospf);
    //         let ip = Ipv4Packet {
    //             dscp: 0,
    //             enc: 0,
    //             identification: 0,
    //             flags: Ipv4Flags {
    //                 mf: false,
    //                 df: false,
    //             },
    //             fragment_offset: 0,
    //             ttl: 64,
    //             proto: PROTO_OSPF,
    //             src: Ipv4Addr::new(107, 170, 2, 3),
    //             dst: Ipv4Addr::new(107, 170, 2, 4),
    //             content: ospf.write_to_bytes().unwrap(),
    //         };
    //         writer
    //             .add_packet(
    //                 &(),
    //                 1000 * i,
    //                 [0xa, 0xb, 0xc, 0xd, 0xe, 0xf],
    //                 [11, 22, 33, 44, 55, 66],
    //                 KIND_IPV4,
    //                 &ip,
    //                 None,
    //             )
    //             .unwrap();
    //     }
    // }
}

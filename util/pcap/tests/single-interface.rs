use bytepack::{FromBytestream, ToBytestream};
use inet_types::{
    ip::{Ipv4Flags, Ipv4Packet},
    udp::UdpPacket,
};
use pcap::{Block, Linktype, PcapFile};
use std::{
    fs::File,
    io::{self, Read},
    net::Ipv4Addr,
};

#[test]
fn read() -> io::Result<()> {
    let mut pcap = File::open("tests/simple-ip-packets.pcap")?;
    let mut buf = Vec::new();
    pcap.read_to_end(&mut buf)?;

    while !buf.is_empty() {
        let block = Block::read_from_vec(&mut buf)?;
        dbg!(block);
    }

    Ok(())
}

#[test]
fn gen() -> io::Result<()> {
    let mut pcap = PcapFile::new(File::create("tests/simple-ip-packets.pcap")?, "alice");
    pcap.record_interface("eth0", "Ethernet 0", "ETH 1500 MSS", Linktype::ETHERNET)?;
    pcap.record_eth_packet(
        "eth0",
        8000,
        &[1 & 0b1111_1100, 2, 3, 4, 5, 6],
        &[6, 5, 4, 3, 2, 1],
        0x0800,
        &Ipv4Packet {
            dscp: 0,
            enc: 0,
            identification: 0,
            flags: Ipv4Flags {
                df: true,
                mf: false,
            },
            fragment_offset: 0,
            ttl: 4,
            proto: 17,
            src: Ipv4Addr::new(192, 168, 2, 101),
            dst: Ipv4Addr::new(10, 1, 0, 1),
            content: UdpPacket {
                src_port: 42481,
                dest_port: 80,
                content: vec![1, 2, 3, 4, 5, 6, 7, 8],
                checksum: 0,
            }
            .to_vec()?,
        },
    )?;

    pcap.record_eth_packet(
        "eth0",
        12000,
        &[1 & 0b1111_1100, 2, 3, 4, 5, 6],
        &[6, 5, 4, 3, 2, 1],
        0x0800,
        &Ipv4Packet {
            dscp: 0,
            enc: 0,
            identification: 0,
            flags: Ipv4Flags {
                df: true,
                mf: false,
            },
            fragment_offset: 0,
            ttl: 4,
            proto: 5,
            src: Ipv4Addr::new(192, 168, 2, 101),
            dst: Ipv4Addr::new(10, 1, 0, 1),
            content: UdpPacket {
                src_port: 42481,
                dest_port: 80,
                content: vec![42; 42],
                checksum: 0,
            }
            .to_vec()?,
        },
    )?;

    Ok(())
}

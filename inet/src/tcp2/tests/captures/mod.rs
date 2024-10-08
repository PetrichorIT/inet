use std::{
    io::{self, Cursor},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use bytepack::ToBytestream;
use pcapng::{BlockWriter, InterfaceDescriptionOption, Linktype, TestBlockWriter};
use types::{
    ip::{Ipv4Flags, Ipv4Packet, KIND_IPV4},
    tcp::PROTO_TCP,
};

use crate::{interface::IfId, tcp2::tests::TcpTestUnit};

impl TcpTestUnit {
    pub fn pipe_and_observe<B: BlockWriter<IfId>>(
        &mut self,
        peer: &mut Self,
        n: usize,
        writer: &mut B,
    ) -> io::Result<()> {
        fn ip_to_eth(ip: Ipv4Addr) -> [u8; 6] {
            let mut buf = [1; 6];
            buf[2..].copy_from_slice(&ip.octets());
            buf
        }

        let n = n.min(self.tx().len());

        let IpAddr::V4(src) = self.quad.src.ip() else {
            todo!("")
        };
        let IpAddr::V4(dst) = peer.quad.src.ip() else {
            todo!("")
        };
        for pkt in self.tx().drain(..n) {
            let ip_packet = Ipv4Packet {
                dscp: 0,
                enc: 0,
                identification: 0,
                flags: Ipv4Flags {
                    df: false,
                    mf: false,
                },
                fragment_offset: 0,
                ttl: 64,
                proto: PROTO_TCP,
                src,
                dst,
                content: pkt.to_vec()?,
            };

            writer.add_packet(
                &IfId::new("eth0"),
                0,
                ip_to_eth(src),
                ip_to_eth(dst),
                KIND_IPV4,
                &ip_packet,
                None,
            )?;

            peer.incoming(pkt)?;
        }
        Ok(())
    }
}

#[test]
fn pcap_test_case() -> io::Result<()> {
    let client_addr = Ipv4Addr::new(10, 0, 1, 104);
    let server_addr = Ipv4Addr::new(20, 0, 2, 204);

    let mut client = TcpTestUnit::new(
        SocketAddr::new(client_addr.into(), 80),   // local
        SocketAddr::new(server_addr.into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(server_addr.into(), 1808), // local
        SocketAddr::new(client_addr.into(), 80),   // peer
    );

    client.cfg.send_buffer_cap = 20_000;
    server.cfg.send_buffer_cap = 20_000;
    client.cfg.iss = Some(2000);
    server.cfg.iss = Some(8000);

    let mut writer = TestBlockWriter::new(
        Cursor::new(include_bytes!("client.pcapng").as_slice()),
        "client",
    )?;
    writer.add_interface(
        &IfId::new("eth0"),
        Linktype::ETHERNET,
        4096,
        vec![
            InterfaceDescriptionOption::InterfaceName("Ethernet 0".to_string()),
            InterfaceDescriptionOption::InterfaceDescription("MSS 1500 SNAP 4096".to_string()),
        ],
    )?;

    client.connect()?;
    client.pipe_and_observe(&mut server, 1, &mut writer)?;

    server.pipe_and_observe(&mut client, 1, &mut writer)?;

    client.pipe_and_observe(&mut server, 1, &mut writer)?;

    let n = client.write(&vec![42; 20_000])?;
    assert_eq!(n, 20_000);

    client.tick()?;
    client.pipe_and_observe(&mut server, 99, &mut writer)?;

    server.pipe_and_observe(&mut client, 99, &mut writer)?;

    Ok(())
}

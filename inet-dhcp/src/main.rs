use std::net::Ipv4Addr;

use bytes_io::ToBytes;
use inet::{UdpSocket, types::iface::MacAddress, utils::SimpleSim};
use inet_dhcp::{DhcpOption, DhcpPacket};
use inet_tuntap::ptun;

fn main() -> Result<(), des::prelude::RuntimeError> {
    des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.node("alice", || async move {
        ptun("utun8")?;

        let sock68 = UdpSocket::bind("0.0.0.0:68").await?;
        sock68.set_broadcast(true)?;

        let sock67 = UdpSocket::bind("0.0.0.0:67").await?;
        sock67.set_broadcast(true)?;

        let discover =
            DhcpPacket::discover(MacAddress::generate(), Some(Ipv4Addr::new(100, 1, 10, 100)));

        sock68
            .send_to(&discover.write_to_bytes()?, "255.255.255.255:67")
            .await?;

        let offer = DhcpPacket::offer(
            &discover,
            Ipv4Addr::new(192, 168, 1, 110),
            Ipv4Addr::new(100, 1, 10, 100),
            vec![
                DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                DhcpOption::Routers(vec![Ipv4Addr::new(100, 1, 10, 1)]),
                DhcpOption::DomainName("alice".to_string()),
                DhcpOption::DomainNameServers(vec![Ipv4Addr::new(100, 1, 10, 1)]),
            ],
        );

        sock67
            .send_to(&offer.write_to_bytes()?, "192.168.2.153:68")
            .await?;

        Ok(())
    });

    sim.node("192.168.2.153", || async move { Ok(()) });

    sim.run()
}

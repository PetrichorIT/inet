use std::fs::File;

use des::runtime::RuntimeError;
use inet::{UdpSocket, utils::SimpleSim};
use inet_pcap::pcap;

#[test]
fn run() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.v6 = true;
    let large_bytes = rand::random::<[u8; 10_000]>();
    let large_bytes_2 = large_bytes.clone();

    sim.node_require_join("alice", move || async move {
        pcap(File::create("out/fragments.pcap")?)?;

        let sock = UdpSocket::bind("[::]:0").await?;
        let n = sock.send_to(&large_bytes, ("bob", 100)).await?;
        assert_eq!(n, 10_000);
        Ok(())
    });

    sim.node_require_join("bob", move || async move {
        let sock = UdpSocket::bind("[::]:100").await?;
        let mut buf = [0; 12_000];
        let (n, _) = sock.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], large_bytes_2);

        Ok(())
    });

    sim.run()
}

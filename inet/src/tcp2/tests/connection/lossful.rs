use super::{TcpTestUnit, WIN_4KB};
use rand::{thread_rng, RngCore};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

impl TcpTestUnit {
    pub fn pipe_lossful(&mut self, peer: &mut Self, n: usize, drop: &[usize]) -> io::Result<()> {
        for (i, pkt) in self.tx.drain(..n.min(self.tx.len())).enumerate() {
            if drop.contains(&i) {
                continue;
            }
            peer.incoming(pkt)?;
        }
        Ok(())
    }
}

#[test]
fn loss_of_data_packets() -> io::Result<()> {
    // des::tracing::init();

    let mut client = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // local
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),   // peer
    );
    client.cfg.send_buffer_cap = (WIN_4KB * 4) as usize;
    client.cfg.enable_congestion_control = true;
    server.cfg.enable_congestion_control = true;

    client.handshake_pipe(&mut server)?;

    let mut bytes = vec![0; WIN_4KB as usize * 4];
    thread_rng().fill_bytes(&mut bytes);

    let n = client.write(&bytes)?;
    assert_eq!(n, WIN_4KB as usize * 4);

    for t in [0.5, 1.0, 1.5, 2.0, 2.5, 3.0] {
        tracing::error!(t, "T");
        client.tick()?;
        client.pipe(&mut server, 100)?;

        client.set_time(t);
        server.set_time(t);

        server.read(&mut vec![0; WIN_4KB as usize])?;

        server.tick()?;
        server.pipe(&mut client, 100)?;

        assert_eq!(client.snd.num_unacked_bytes(), 0);
    }

    tracing::debug!("real test case begins");

    assert_eq!(client.num_unsend_bytes(), Some(6584));
    assert_eq!(client.snd.c.cwnd, 2144);

    client.tick()?;
    client.pipe_lossful(&mut server, 100, &[1])?;

    client.set_time(10.0);
    server.set_time(10.0);

    // buffer packets have been dropped
    server.tick()?;
    assert_eq!(server.incoming.pkts, []);

    // pipe new packets
    client.tick()?;
    client.pipe(&mut server, 100)?;
    Ok(())
}

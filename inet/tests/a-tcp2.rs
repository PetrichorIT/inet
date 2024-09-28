use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    ops::Deref,
    sync::{Arc, Mutex},
};

use des::time::SimTime;
use inet::tcp2::{Config, Connection, Quad, State, TcpHandle};
use inet_types::tcp::TcpPacket;
use tracing::instrument;

struct TcpTestUnit {
    handle: TcpHandle,
    con: Option<Connection>,
    cfg: Config,
    clock: Arc<Mutex<SimTime>>,
}

impl TcpTestUnit {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        let clock = Arc::new(Mutex::new(SimTime::ZERO));
        let clock_reader = clock.clone();
        Self {
            handle: TcpHandle {
                quad: Quad { src, dst },
                tx_buffer: Vec::new(),
            },
            con: None,
            clock,
            cfg: Config {
                clock: Arc::new(move || *clock_reader.lock().unwrap()),
                ..Default::default()
            },
        }
    }

    pub fn cfg(&mut self, cfg: Config) {
        self.cfg = cfg;
    }

    pub fn connect(&mut self) -> io::Result<()> {
        assert!(self.con.is_none());
        self.con = Some(Connection::connect(&mut self.handle, self.cfg.clone())?);
        Ok(())
    }

    pub fn incoming(&mut self, pkt: TcpPacket) -> io::Result<()> {
        if let Some(ref mut con) = self.con {
            con.on_packet(&mut self.handle, pkt)?;
        } else {
            self.con = Connection::accept(&mut self.handle, pkt, self.cfg.clone())?;
        }
        Ok(())
    }

    pub fn pipe(&mut self, peer: &mut Self, n: usize) -> io::Result<()> {
        for pkt in self.handle.tx_buffer.drain(..n) {
            peer.incoming(pkt)?;
        }
        Ok(())
    }

    pub fn next_timeout(&self) -> Option<SimTime> {
        self.con.as_ref().and_then(|v| v.next_timeout())
    }

    pub fn assert_connection_exists(&self) {
        assert!(
            self.con.is_some(),
            "no connection exists: handshake must have failed"
        );
    }

    pub fn assert_connection_established(&self) {
        self.assert_connection_exists();
        assert!(
            self.con.as_ref().unwrap().is_synchronized(),
            "connection ont syncronized"
        );
    }

    pub fn assert_outgoing(&mut self, f: impl FnOnce(Vec<TcpPacket>)) {
        assert!(
            self.con.is_some(),
            "no connection exists: expected on assert outing"
        );
        f(self.handle.tx_buffer.drain(..).collect())
    }

    pub fn assert_outgoing_eq(&mut self, pkts: &[TcpPacket]) {
        self.assert_outgoing(|outgoing| {
            assert_eq!(outgoing.len(), pkts.len());
            assert_eq!(outgoing, pkts)
        });
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.con
            .as_mut()
            .expect("no connection exists: cannot write")
            .write(buf)
    }

    pub fn set_time(&self, now: impl Into<SimTime>) {
        *self.clock.lock().unwrap() = now.into();
    }

    #[instrument(skip_all)]
    pub fn tick(&mut self) -> io::Result<()> {
        self.con
            .as_mut()
            .expect("no connection exists: cannot tick")
            .on_tick(&mut self.handle)
    }

    pub fn clear_outgoing(&mut self) {
        self.handle.tx_buffer.clear();
    }

    pub fn handshake(&mut self, remote_seq_no: u32, remote_recv_window: u16) -> io::Result<()> {
        self.incoming(TcpPacket::syn(
            self.handle.quad.dst.port(),
            self.handle.quad.src.port(),
            remote_seq_no,
            remote_recv_window,
        ))?;
        self.assert_connection_exists();
        self.clear_outgoing();

        self.incoming(TcpPacket::data(
            self.handle.quad.dst.port(),
            self.handle.quad.src.port(),
            remote_seq_no + 1,
            1,
            remote_recv_window,
            vec![],
        ))?;
        self.clear_outgoing();
        Ok(())
    }
}

impl Deref for TcpTestUnit {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self
            .con
            .as_ref()
            .expect("Deref can only be used on existing connections")
    }
}

#[test]
fn handshake() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.incoming(TcpPacket::syn(1808, 80, 4000, 1024))?;
    test.assert_connection_exists();

    let mut syn_ack = TcpPacket::syn(80, 1808, 0, 4096);
    syn_ack.flags = syn_ack.flags.ack(true);
    syn_ack.ack_no = 4001;
    test.assert_outgoing_eq(&[syn_ack]);

    test.incoming(TcpPacket::data(
        1808,
        80,
        4001,
        1,
        1024,
        vec![1, 2, 3, 4, 5, 5, 7, 8],
    ))?;
    test.assert_outgoing_eq(&[TcpPacket::data(80, 1808, 1, 4009, 4096 - 8, Vec::new())]);

    Ok(())
}

#[test]
fn handshake_connect() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    // -> SYN
    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, 4096).with_mss(536)]);

    // <- SYNACK
    // -> ACK
    let mut syn_ack = TcpPacket::syn(1808, 80, 4000, 4096).with_mss(536);
    syn_ack.ack_no = 1;
    syn_ack.flags.ack = true;
    test.incoming(syn_ack)?;
    test.assert_outgoing_eq(&[TcpPacket::data(80, 1808, 1, 4001, 4096, Vec::new())]);

    Ok(())
}

#[test]
fn handshake_connect_syn_timeout() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    // -> SYN
    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, 4096).with_mss(536)]);
    assert_eq!(test.next_timeout(), Some(15.0.into()));

    test.tick()?;
    test.assert_outgoing_eq(&[]);

    test.set_time(15.0);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, 4096).with_mss(536)]);

    // <- SYNACK
    // -> ACK
    let mut syn_ack = TcpPacket::syn(1808, 80, 4000, 4096).with_mss(536);
    syn_ack.ack_no = 1;
    syn_ack.flags.ack = true;

    test.set_time(17.0);
    test.incoming(syn_ack)?;
    test.assert_outgoing_eq(&[TcpPacket::data(80, 1808, 1, 4001, 4096, Vec::new())]);

    Ok(())
}

#[test]
fn handshake_connect_closed_after_too_many_syn_timeouts() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    // -> SYN (initial)
    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, 4096).with_mss(536)]);
    assert_eq!(test.next_timeout(), Some(15.0.into()));

    // repeats nr 1,2,3
    for t in [15.0, 30.0, 45.0] {
        test.set_time(t);
        test.tick()?;
        test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, 4096).with_mss(536)]);
        assert_eq!(test.state, State::SynSent);
    }

    // full timeout
    test.set_time(60.0);
    test.tick()?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::Closed);

    Ok(())
}

#[test]
fn handshake_connect_regulated_mss() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, 4096).with_mss(536)]);

    let mut syn_ack = TcpPacket::syn(1808, 80, 4000, 4096).with_mss(400);
    syn_ack.ack_no = 1;
    syn_ack.flags.ack = true;
    test.incoming(syn_ack)?;
    test.assert_outgoing_eq(&[TcpPacket::data(80, 1808, 1, 4001, 4096, Vec::new()).with_mss(400)]);
    assert_eq!(test.mss, 400);

    Ok(())
}

#[test]
fn handshake_connect_rst_in_syn_sent() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );

    test.connect()?;
    test.assert_outgoing_eq(&[TcpPacket::syn(80, 1808, 0, 4096).with_mss(536)]);

    let rst = TcpPacket::rst_for_syn(&TcpPacket::syn(80, 1808, 0, 4096).with_mss(536));
    test.incoming(rst)?;
    test.assert_outgoing_eq(&[]);
    assert_eq!(test.state, State::Closed);

    Ok(())
}

#[test]
fn handshake_e2e() -> io::Result<()> {
    let mut client = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80), // local
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // peer
    );
    let mut server = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808), // local
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),   // peer
    );

    client.connect()?;
    client.assert_connection_exists();

    // client -> server :: SYN
    client.pipe(&mut server, 1)?;
    client.assert_outgoing_eq(&[]);

    // server -> client SYN ACK
    server.pipe(&mut client, 1)?;
    server.assert_outgoing_eq(&[]);
    client.assert_connection_established();

    client.pipe(&mut server, 1)?;
    client.assert_outgoing_eq(&[]);
    server.assert_connection_established();

    Ok(())
}

#[test]
fn transmitt_data_after_handshake() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );

    test.handshake(4000, 1024)?;

    assert_eq!(test.write(&[1, 2, 3, 4, 5, 6, 7, 8])?, 8);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::data(
        80,
        1808,
        1,
        4001,
        4096,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
    )]);

    assert_eq!(test.write(&[8, 7, 6, 5, 4, 3, 2, 1])?, 8);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::data(
        80,
        1808,
        1 + 8,
        4001,
        4096,
        vec![8, 7, 6, 5, 4, 3, 2, 1],
    )]);

    Ok(())
}

#[test]
fn tx_limited_by_peers_recv_window() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );
    test.cfg(Config {
        send_buffer_cap: 4 * 1024,
        recv_buffer_cap: 1024,
        mss: Some(1400),
        ..Default::default()
    });

    test.handshake(4000, 1024)?;

    let data: Vec<u8> = (0..).map(|v| (v % 256) as u8).take(4 * 1024).collect();

    assert_eq!(test.write(&data)?, 4 * 1024);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::data(
        80,
        1808,
        1,
        4001,
        1024,
        data[..1024].to_vec(),
    )]);

    test.tick()?;
    test.assert_outgoing_eq(&[]);

    test.incoming(TcpPacket::data(1808, 80, 4001, 1 + 1 * 1024, 0, Vec::new()))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[]);

    // Buffer is free once more
    // -> no direct ack, since no data was send
    // -> new send packet on tick
    test.incoming(TcpPacket::data(
        1808,
        80,
        4001,
        1 + 1 * 1024,
        1024,
        Vec::new(),
    ))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::data(
        80,
        1808,
        1 + 1024,
        4001,
        1024,
        data[1024..2048].to_vec(),
    )]);

    // Direct ack + window clear
    // -> no ACK but Datat
    test.incoming(TcpPacket::data(
        1808,
        80,
        4001,
        1 + 2 * 1024,
        1024,
        Vec::new(),
    ))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::data(
        80,
        1808,
        1 + 2 * 1024,
        4001,
        1024,
        data[2048..3072].to_vec(),
    )]);

    // Direct ack + window clear
    // -> no ACK but Datat
    test.incoming(TcpPacket::data(
        1808,
        80,
        4001,
        1 + 3 * 1024,
        1024,
        Vec::new(),
    ))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::data(
        80,
        1808,
        1 + 3 * 1024,
        4001,
        1024,
        data[3072..].to_vec(),
    )]);

    // no more data after final bytes
    test.incoming(TcpPacket::data(
        1808,
        80,
        4001,
        1 + 4 * 1024,
        1024,
        Vec::new(),
    ))?;
    test.assert_outgoing_eq(&[]);
    test.tick()?;
    test.assert_outgoing_eq(&[]);

    Ok(())
}

#[test]
fn tx_can_emit_multiple_packets() -> io::Result<()> {
    let mut test = TcpTestUnit::new(
        SocketAddr::new(Ipv4Addr::new(10, 0, 1, 104).into(), 80),
        SocketAddr::new(Ipv4Addr::new(20, 0, 2, 204).into(), 1808),
    );
    test.cfg(Config {
        send_buffer_cap: 4 * 1024,
        recv_buffer_cap: 4 * 1024,
        mss: Some(1400),
        ..Default::default()
    });

    test.handshake(4000, 3000)?;

    let data: Vec<u8> = (0..).map(|v| (v % 256) as u8).take(4 * 1024).collect();
    assert_eq!(4096, test.write(&data)?);

    test.tick()?;
    test.assert_outgoing_eq(&[
        TcpPacket::data(80, 1808, 1, 4001, 4096, data[..1400].to_vec()),
        TcpPacket::data(80, 1808, 1 + 1400, 4001, 4096, data[1400..2800].to_vec()),
        TcpPacket::data(
            80,
            1808,
            1 + 2 * 1400,
            4001,
            4096,
            data[2800..3000].to_vec(),
        ),
    ]);

    test.tick()?;
    test.assert_outgoing_eq(&[]);

    test.incoming(TcpPacket::data(
        1808,
        80,
        4001,
        3001,
        4096 - 3000,
        Vec::new(),
    ))?;
    test.tick()?;
    test.assert_outgoing_eq(&[TcpPacket::data(
        80,
        1808,
        3001,
        4001,
        4096,
        data[3000..].to_vec(),
    )]);

    Ok(())
}

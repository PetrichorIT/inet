use std::{
    io,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, Mutex},
};

use crate::{
    interface::IfId,
    tcp2::{Config, Connection, Quad, State, TcpHandle},
};
use des::time::SimTime;
use pcapng::BlockWriter;
use tracing::instrument;
use types::tcp::TcpPacket;

pub(super) const WIN_4KB: u16 = 4096;

pub(super) struct TcpTestUnit {
    pub(super) handle: TcpHandle,
    pub(super) con: Option<Connection>,
    pub(super) cfg: Config,
    pub(super) clock: Arc<Mutex<SimTime>>,
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

    pub fn pipe_and_expect(
        &mut self,
        peer: &mut Self,
        n: usize,
        pkts: &[TcpPacket],
    ) -> io::Result<()> {
        for (i, pkt) in self.handle.tx_buffer.drain(..n).enumerate() {
            assert_eq!(pkt, pkts[i]);
            peer.incoming(pkt)?;
        }
        Ok(())
    }

    pub fn next_timeout(&self) -> Option<SimTime> {
        self.con.as_ref().and_then(|v| v.next_timeout())
    }

    pub fn close(&mut self) -> io::Result<()> {
        if let Some(ref mut v) = self.con {
            v.close()
        } else {
            Ok(())
        }
    }

    pub fn assert_connection_exists(&self) {
        assert!(
            self.con.is_some(),
            "no connection exists: handshake must have failed"
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
            assert_eq!(outgoing, pkts);
        });
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.con
            .as_mut()
            .expect("no connection exists: cannot write")
            .write(buf)
    }

    pub fn write_and_ack(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.write(buf)?;
        self.tick()?;

        let last = self.handle.tx_buffer.pop().unwrap();
        self.clear_outgoing();

        // Collective ACK
        self.incoming(TcpPacket::new(
            self.quad.dst.port(),
            self.quad.src.port(),
            self.recv.nxt,
            last.seq_no + last.content.len() as u32,
            WIN_4KB,
            Vec::new(),
        ))?;

        Ok(n)
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

        self.incoming(TcpPacket::new(
            self.handle.quad.dst.port(),
            self.handle.quad.src.port(),
            remote_seq_no + 1,
            1,
            remote_recv_window,
            vec![],
        ))?;
        self.clear_outgoing();
        assert_eq!(self.state, State::Estab);
        Ok(())
    }

    pub fn handshake_pipe(&mut self, server: &mut Self) -> io::Result<()> {
        self.connect()?;
        self.pipe(server, 1)?;
        server.pipe(self, 1)?;
        self.pipe(server, 1)?;

        assert_eq!(self.state, State::Estab);
        assert_eq!(server.state, State::Estab);
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

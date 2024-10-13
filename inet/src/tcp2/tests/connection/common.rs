use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, Mutex},
};

use crate::tcp2::{sender::TcpSender, Config, Connection, Quad, State};
use des::time::SimTime;
use tracing::instrument;
use types::tcp::TcpPacket;

pub(in crate::tcp2::tests) const WIN_4KB: u16 = 4096;

pub(in crate::tcp2::tests) struct TcpTestUnit {
    pub tx: VecDeque<TcpPacket>,
    pub quad: Quad,
    pub con: Option<Connection>,
    pub cfg: Config,
    pub clock: Arc<Mutex<SimTime>>,
}

impl TcpTestUnit {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        let clock = Arc::new(Mutex::new(SimTime::ZERO));
        let clock_reader = clock.clone();
        Self {
            tx: VecDeque::default(),
            quad: Quad { src, dst },
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
        self.con = Some(Connection::connect(
            &mut TcpSender {
                buffer: &mut self.tx,
                unresolved_wakeups: &mut false,
            },
            self.quad.clone(),
            self.cfg.clone(),
        )?);
        Ok(())
    }

    pub fn incoming(&mut self, pkt: TcpPacket) -> io::Result<()> {
        if let Some(ref mut con) = self.con {
            con.on_packet(
                &mut TcpSender {
                    buffer: &mut self.tx,
                    unresolved_wakeups: &mut false,
                },
                pkt,
            )?;
        } else {
            self.con = Connection::accept(
                &mut TcpSender {
                    buffer: &mut self.tx,
                    unresolved_wakeups: &mut false,
                },
                self.quad.clone(),
                pkt,
                self.cfg.clone(),
            )?;
        }
        Ok(())
    }

    pub fn pipe(&mut self, peer: &mut Self, n: usize) -> io::Result<()> {
        for pkt in self.tx.drain(..n) {
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
        for (i, pkt) in self.tx.drain(..n).enumerate() {
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
        f(self.tx.drain(..).collect())
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

        let last = self.tx.pop_back().unwrap();
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
            .on_tick(&mut TcpSender {
                buffer: &mut self.tx,
                unresolved_wakeups: &mut false,
            })
    }

    pub fn clear_outgoing(&mut self) {
        self.tx.clear();
    }

    pub fn handshake(&mut self, remote_seq_no: u32, remote_recv_window: u16) -> io::Result<()> {
        self.incoming(TcpPacket::syn(
            self.quad.dst.port(),
            self.quad.src.port(),
            remote_seq_no,
            remote_recv_window,
        ))?;
        self.assert_connection_exists();
        self.clear_outgoing();

        self.incoming(TcpPacket::new(
            self.quad.dst.port(),
            self.quad.src.port(),
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

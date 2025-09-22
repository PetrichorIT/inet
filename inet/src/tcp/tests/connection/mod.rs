use std::{
    collections::VecDeque,
    fs::File,
    io,
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
    path::Path,
    sync::{Arc, Mutex},
};

use crate::tcp::{Config, Connection, Quad, State};
use bytes_io::ToBytes;
use des::time::SimTime;
use pcapng::{BlockWriter, DefaultBlockWriter, InterfaceDescriptionOption, Linktype};
use tracing::instrument;
use types::{
    ip::{Ipv4Flags, Ipv4Packet, Ipv6Packet, KIND_IPV4, KIND_IPV6},
    tcp::{PROTO_TCP, TcpPacket},
};

mod cong;
mod dup_ack;
mod handshake;
mod icmp;
mod lossful;
mod out_of_order;
mod rst;
mod rtt;
mod sack;
mod shutdown;
mod transfer;

pub(in crate::tcp::tests) const WIN_4KB: u16 = 4096;

pub(in crate::tcp::tests) struct TcpTestUnit {
    pub quad: Quad,
    pub con: Option<Connection>,
    pub cfg: Config,
    pub clock: Arc<Mutex<SimTime>>,
    pub recorder: Option<DefaultBlockWriter<File, ()>>,
}

impl TcpTestUnit {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        let clock = Arc::new(Mutex::new(SimTime::ZERO));
        let clock_reader = clock.clone();
        Self {
            quad: Quad { src, dst },
            con: None,
            clock,
            cfg: Config {
                clock: Arc::new(move || *clock_reader.lock().unwrap()),
                ..Config::test_default()
            },
            recorder: None,
        }
    }

    #[allow(unused)]
    pub fn set_recorder(&mut self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut recorder = DefaultBlockWriter::new(File::create(path)?, "test-case-recording")?;
        recorder.add_interface(
            &(),
            Linktype::ETHERNET,
            4096,
            vec![InterfaceDescriptionOption::InterfaceName(
                "Ethernet".to_string(),
            )],
        )?;
        self.recorder = Some(recorder);
        Ok(())
    }

    pub fn cfg(&mut self, cfg: Config) {
        self.cfg = cfg;
    }

    pub fn connect(&mut self) -> io::Result<()> {
        assert!(self.con.is_none());
        self.con = Some(Connection::connect(self.quad.clone(), self.cfg.clone())?);
        Ok(())
    }

    pub fn incoming(&mut self, pkt: TcpPacket) -> io::Result<()> {
        record(&mut self.recorder, &pkt, self.quad.reversed())?;
        if let Some(ref mut con) = self.con {
            con.on_packet(pkt)?;
        } else {
            self.con = Connection::accept(self.quad.clone(), pkt, self.cfg.clone())?;
        }
        Ok(())
    }

    pub fn pipe(&mut self, peer: &mut Self, n: usize) -> io::Result<()> {
        let n = n.min(tx(&mut self.con).len());
        for pkt in tx(&mut self.con).drain(..n) {
            record(&mut self.recorder, &pkt, self.quad)?;
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
        for (i, pkt) in tx(&mut self.con).drain(..n).enumerate() {
            record(&mut self.recorder, &pkt, self.quad)?;
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

    #[track_caller]
    pub fn assert_outgoing(&mut self, f: impl FnOnce(Vec<TcpPacket>)) {
        assert!(
            self.con.is_some(),
            "no connection exists: expected on assert outing"
        );

        if self
            .con
            .as_ref()
            .map_or(false, |con| con.cfg.enable_queue_optimizations)
        {
            self.optimize_queue_elements();
        }

        f(tx(&mut self.con)
            .drain(..)
            .map(|pkt| {
                record(&mut self.recorder, &pkt, self.quad).unwrap();
                pkt
            })
            .collect())
    }

    #[track_caller]
    pub fn assert_outgoing_eq(&mut self, pkts: &[TcpPacket]) {
        self.assert_outgoing(|outgoing| {
            assert_eq!(outgoing.len(), pkts.len(), "unequal number of packets");
            for (i, (outgoing, pkt)) in outgoing.iter().zip(pkts).enumerate() {
                assert_eq!(
                    outgoing,
                    pkt,
                    "packet at index {} does not match:\n body len {} :: {}",
                    i,
                    outgoing.content.len(),
                    pkt.content.len(),
                );
            }
        });
    }

    pub fn write_and_ack(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.write(buf)?;
        self.tick()?;

        let last = tx(&mut self.con).pop_back().unwrap();
        self.clear_outgoing();

        // Collective ACK
        self.incoming(TcpPacket::new(
            self.quad.dst.port(),
            self.quad.src.port(),
            self.rcv.nxt,
            last.seq_no + last.content.len() as u32,
            WIN_4KB,
            Vec::new(),
        ))?;

        Ok(n)
    }

    pub fn set_time(&self, now: impl Into<SimTime>) {
        let now = now.into();
        tracing::info!("set_time({:?})", now);
        *self.clock.lock().unwrap() = now;
    }

    #[instrument(skip_all)]
    pub fn tick(&mut self) -> io::Result<()> {
        self.con
            .as_mut()
            .expect("no connection exists: cannot tick")
            .on_tick()
    }

    pub fn clear_outgoing(&mut self) {
        self.assert_outgoing(|_| {});
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
        self.con
            .as_ref()
            .expect("Deref can only be used on existing connections")
    }
}

impl DerefMut for TcpTestUnit {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.con
            .as_mut()
            .expect("Deref can only be used on existing connections")
    }
}

fn tx(con: &mut Option<Connection>) -> &mut VecDeque<TcpPacket> {
    con.as_mut()
        .map(|con| &mut con.outgoing)
        .expect("cannot test tx, where not connection exists")
}

fn record(
    recorder: &mut Option<DefaultBlockWriter<File, ()>>,
    pkt: &TcpPacket,
    quad: Quad,
) -> io::Result<()> {
    if let Some(recorder) = recorder.as_mut() {
        let ts = SimTime::now().as_millis() as u64;

        match (quad.src.ip(), quad.dst.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                recorder.add_packet(
                    &(),
                    ts,
                    [0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0],
                    KIND_IPV4,
                    &Ipv4Packet {
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
                        content: pkt.write_to_bytes()?,
                    },
                    None,
                )?;
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                recorder.add_packet(
                    &(),
                    ts,
                    [0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0],
                    KIND_IPV6,
                    &Ipv6Packet {
                        traffic_class: 0,
                        flow_label: 0,
                        proto: PROTO_TCP,
                        hop_limit: 64,
                        extension_headers: Vec::new(),
                        src,
                        dst,
                        content: pkt.write_to_bytes_mut()?.freeze(),
                    },
                    None,
                )?;
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

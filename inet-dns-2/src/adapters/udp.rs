use bytepack::{FromBytestream, ToBytestream};
use inet::UdpSocket;
use tokio::{sync::mpsc::Sender, task::JoinHandle};

use crate::{
    core::OptResourceRecord,
    server::{DnsMessage, FinishedTransaction, Nameserver, NameserverQuery, TransportMedium},
};

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use super::{TransportAdapter, DEFAULT_PORT};

/// A UDP transport adapter for DNS queries.
///
/// This adapter implements conventional DNS over UDP as specified in RFC 1035
pub struct UdpAdapter {
    port: u16,
    edns: bool,
    socket: Option<Arc<UdpSocket>>,
    handle: Option<JoinHandle<()>>,
}

impl UdpAdapter {
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_edns(mut self, edns: bool) -> Self {
        self.edns = edns;
        self
    }

    fn udp_limit(&self, inc: &Option<OptResourceRecord>) -> usize {
        if let Some(inc) = inc {
            if self.edns {
                return inc.udp_payload_size as usize;
            }
        }
        516
    }
}

#[async_trait::async_trait]
impl TransportAdapter for UdpAdapter {
    async fn deploy(
        &mut self,
        tx: Sender<(TransportMedium, SocketAddr, DnsMessage)>,
    ) -> io::Result<()> {
        let udp = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, self.port)).await?);
        self.socket = Some(udp.clone());

        self.handle = Some(tokio::spawn(async move {
            let tx = tx;
            let mut buf = vec![0; 512];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    tracing::error!("failed to recv datagram from socket");
                    return;
                };

                let Ok(msg) = DnsMessage::from_slice(&buf[..n]) else {
                    tracing::error!("invalid packet");
                    continue;
                };

                if let Err(err) = tx.send((TransportMedium::Udp, from, msg)).await {
                    tracing::error!("failed to dispatch event: {}", err);
                    return;
                }
            }
        }));

        Ok(())
    }

    async fn send_anwser(&mut self, anwser: FinishedTransaction) -> io::Result<()> {
        let Some(ref socket) = self.socket else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "socket not initialized",
            ));
        };

        let target = anwser.query.addr;

        let mut buf = vec![0u8; self.udp_limit(&anwser.query.edns)];
        let mut msg = DnsMessage::response_from_transaction(anwser).with_edns(self.edns);
        let n = loop {
            match msg.to_buf(&mut buf) {
                Ok(n) => break n,
                Err(w) if w.kind() == io::ErrorKind::WriteZero => {
                    msg.truncate();
                }
                Err(e) => return Err(e),
            }
        };

        socket.send_to(&buf[..n], target).await?;
        Ok(())
    }

    async fn send_ns_query(&mut self, ns_query: NameserverQuery) -> io::Result<()> {
        let Some(ref socket) = self.socket else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "socket not initialized",
            ));
        };

        let target = SocketAddr::new(ns_query.nameserver_ip, DEFAULT_PORT);

        let mut buf = vec![0u8; self.udp_limit(&ns_query.query.edns)];
        let mut msg = DnsMessage::request_from_ns_query(ns_query).with_edns(self.edns);
        let n = loop {
            match msg.to_buf(&mut buf) {
                Ok(n) => break n,
                Err(w) if w.kind() == io::ErrorKind::WriteZero => {
                    msg.truncate();
                }
                Err(e) => return Err(e),
            }
        };
        socket.send_to(&buf[..n], target).await?;

        Ok(())
    }

    async fn tick(&mut self, _: &dyn Nameserver) -> io::Result<()> {
        Ok(())
    }
}

impl Default for UdpAdapter {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            edns: true,
            socket: None,
            handle: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use inet::{test_util::SimpleSim, utils::get_ip};
    use serial_test::serial;
    use tokio::sync::mpsc;

    use crate::{
        adapters::Base,
        core::{
            AAAAResourceRecord, AResourceRecord, DnsString, QueryResponse, Question, QuestionClass,
            QuestionTyp, ResourceRecordClass, ResponseCode, ZoneResolver, Zonefile,
        },
        server::{IterativeNameserver, RecursiveNameserver, SourceQuery, TransactionResult},
    };

    use super::*;

    const ZONEFILE_ROOT: &str = include_str!("../examples/root.zone");
    const ZONEFILE_ORG: &str = include_str!("../examples/org.zone");
    const ZONEFILE_EXAMPLE_ORG: &str = include_str!("../examples/example.org.zone");

    #[test]
    #[serial]
    fn iterative_simple_anwser() {
        let mut sim = SimpleSim::new(inet::init);
        sim.node("192.168.2.10", || async move {
            let zone = ZoneResolver::new(ZONEFILE_ORG.parse()?)?;
            let recu = IterativeNameserver::primary(vec![zone]);
            let server = Base::new(recu).with_adapter(TransportMedium::Udp, UdpAdapter::default());
            tokio::spawn(server.deploy());

            Ok(())
        });

        sim.node_require_join("192.168.2.101", || async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await?;
            sock.send_to(
                &DnsMessage::question_a(1, "rss.info.org.".parse()?).to_vec()?,
                ("192.168.2.10", DEFAULT_PORT),
            )
            .await?;

            let mut buf = vec![0; 512];
            let (n, _) = sock.recv_from(&mut buf).await?;
            let msg = DnsMessage::from_slice(&buf[..n])?;
            assert_eq!(msg.response.anwsers.len(), 1);

            Ok(())
        });

        let _ = sim.run();
    }

    #[test]
    #[serial]
    fn iterative_simple_auth() {
        let mut sim = SimpleSim::new(inet::init);
        sim.node("192.168.2.10", || async move {
            let zone = ZoneResolver::new(ZONEFILE_ORG.parse()?)?;
            let recu = IterativeNameserver::primary(vec![zone]);
            let server = Base::new(recu).with_adapter(TransportMedium::Udp, UdpAdapter::default());
            tokio::spawn(server.deploy());

            Ok(())
        });

        sim.node_require_join("192.168.2.101", || async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await?;
            sock.send_to(
                &DnsMessage::question_a(1, "alice.example.org.".parse()?).to_vec()?,
                ("192.168.2.10", DEFAULT_PORT),
            )
            .await?;

            let mut buf = vec![0; 512];
            let (n, _) = sock.recv_from(&mut buf).await?;
            let msg = DnsMessage::from_slice(&buf[..n])?;
            assert_eq!(msg.response.auths.len(), 1);

            Ok(())
        });

        let _ = sim.run();
    }

    #[test]
    #[serial]
    fn iterative_error_propagation() {
        let mut sim = SimpleSim::new(inet::init);
        sim.node("192.168.2.10", || async move {
            let zone = ZoneResolver::new(ZONEFILE_ORG.parse()?)?;
            let recu = IterativeNameserver::primary(vec![zone]);
            let server = Base::new(recu).with_adapter(TransportMedium::Udp, UdpAdapter::default());
            tokio::spawn(server.deploy());

            Ok(())
        });

        sim.node_require_join("192.168.2.101", || async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await?;
            sock.send_to(
                &DnsMessage::question_a(1, "alice.example.net.".parse()?).to_vec()?,
                ("192.168.2.10", DEFAULT_PORT),
            )
            .await?;

            let mut buf = vec![0; 512];
            let (n, _) = sock.recv_from(&mut buf).await?;
            let msg = DnsMessage::from_slice(&buf[..n])?;
            assert_eq!(msg.rcode, ResponseCode::NotZone);

            Ok(())
        });

        let _ = sim.run();
    }

    #[test]
    #[serial]
    fn recursive_queries() {
        let mut sim = SimpleSim::new(inet::init);

        // Authoratives

        sim.node("192.168.2.10", || async move {
            let zone = ZoneResolver::new(ZONEFILE_ROOT.parse()?)?;
            let auth = IterativeNameserver::primary(vec![zone]);
            let server = Base::new(auth)
                .set_root(true)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default());
            server.deploy().await
        });

        sim.node("192.168.2.20", || async move {
            let zone = ZoneResolver::new(ZONEFILE_ORG.parse()?)?;
            let auth = IterativeNameserver::primary(vec![zone]);
            let server = Base::new(auth).with_adapter(TransportMedium::Udp, UdpAdapter::default());
            server.deploy().await
        });

        sim.node("192.168.2.30", || async move {
            let zone = ZoneResolver::new(ZONEFILE_EXAMPLE_ORG.parse()?)?;
            let auth = IterativeNameserver::primary(vec![zone]);
            let server = Base::new(auth).with_adapter(TransportMedium::Udp, UdpAdapter::default());
            server.deploy().await
        });

        // Resolver

        sim.node("192.168.2.100", || async move {
            let recu = RecursiveNameserver::new(Zonefile::local())?
                .with_roots(vec![(Ipv4Addr::new(192, 168, 2, 10).into(), String::new())]);
            let server = Base::new(recu).with_adapter(TransportMedium::Udp, UdpAdapter::default());
            server.deploy().await
        });

        // client

        sim.node_require_join("192.168.2.101", || async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await?;
            sock.send_to(
                &DnsMessage::question_a(1, "alice.example.org.".parse()?).to_vec()?,
                ("192.168.2.100", DEFAULT_PORT),
            )
            .await?;

            let mut buf = vec![0; 512];
            let (n, _) = sock.recv_from(&mut buf).await?;
            let msg = DnsMessage::from_slice(&buf[..n])?;

            assert_eq!(msg.response.anwsers.len(), 1);

            Ok(())
        });

        let _ = sim.run();
    }

    #[test]
    #[serial]
    fn truncated_execssive_response() -> Result<(), des::prelude::RuntimeError> {
        let mut sim = SimpleSim::new(inet::init);
        sim.node_require_join("alice", || async move {
            let recv = UdpSocket::bind("0.0.0.0:2000").await?;

            let (tx, _) = mpsc::channel(1);
            let mut adapter = UdpAdapter::default().with_port(3000);
            adapter.deploy(tx).await?;

            let mut resp = QueryResponse::default();
            for _ in 0..20 {
                resp.anwsers.push(
                    AResourceRecord {
                        name: "alice.example.org.".parse().unwrap(),
                        ttl: 3600,
                        class: ResourceRecordClass::IN,
                        addr: Ipv4Addr::new(127, 0, 0, 1),
                    }
                    .into(),
                );
                resp.additional.push(
                    AAAAResourceRecord {
                        name: "alice.example.org.".parse().unwrap(),
                        ttl: 3600,
                        class: ResourceRecordClass::IN,
                        addr: Ipv6Addr::new(127, 0, 0, 1, 0, 0, 0, 1),
                    }
                    .into(),
                );
            }

            adapter
                .send_anwser(FinishedTransaction {
                    query: Arc::new(SourceQuery {
                        medium: TransportMedium::Udp,
                        edns: None,
                        addr: SocketAddr::new(get_ip().unwrap(), 2000),
                        transaction: 1,
                        question: Question {
                            qtyp: QuestionTyp::A,
                            qclass: QuestionClass::IN,
                            qname: "alice.example.org.".parse().unwrap(),
                        },
                    }),
                    aa: true,
                    ra: true,
                    result: TransactionResult::Success(resp),
                })
                .await?;

            let mut buf = vec![0; 1012];
            let (n, _) = recv.recv_from(&mut buf).await?;
            let msg = DnsMessage::from_slice(&buf[..n])?;

            assert_eq!(msg.response.anwsers.len(), 15);
            assert_eq!(msg.response.additional.len(), 0);

            Ok(())
        });

        sim.run()
    }

    #[test]
    #[serial]
    fn truncated_higher_limit_with_edns() -> Result<(), des::prelude::RuntimeError> {
        let mut sim = SimpleSim::new(inet::init);
        sim.node_require_join("alice", || async move {
            let recv = UdpSocket::bind("0.0.0.0:2000").await?;

            let (tx, _) = mpsc::channel(1);
            let mut adapter = UdpAdapter::default().with_port(3000);
            adapter.deploy(tx).await?;

            let mut resp = QueryResponse::default();
            for _ in 0..20 {
                resp.anwsers.push(
                    AResourceRecord {
                        name: "alice.example.org.".parse().unwrap(),
                        ttl: 3600,
                        class: ResourceRecordClass::IN,
                        addr: Ipv4Addr::new(127, 0, 0, 1),
                    }
                    .into(),
                );
                resp.additional.push(
                    AAAAResourceRecord {
                        name: "alice.example.org.".parse().unwrap(),
                        ttl: 3600,
                        class: ResourceRecordClass::IN,
                        addr: Ipv6Addr::new(127, 0, 0, 1, 0, 0, 0, 1),
                    }
                    .into(),
                );
            }

            adapter
                .send_anwser(FinishedTransaction {
                    query: Arc::new(SourceQuery {
                        medium: TransportMedium::Udp,
                        edns: Some(
                            OptResourceRecord {
                                name: DnsString::empty(),
                                udp_payload_size: 1200,
                                rcode: 0,
                                version: true,
                                options: Vec::new(),
                            }
                            .into(),
                        ),
                        addr: SocketAddr::new(get_ip().unwrap(), 2000),
                        transaction: 1,
                        question: Question {
                            qtyp: QuestionTyp::A,
                            qclass: QuestionClass::IN,
                            qname: "alice.example.org.".parse().unwrap(),
                        },
                    }),
                    aa: true,
                    ra: true,
                    result: TransactionResult::Success(resp),
                })
                .await?;

            let mut buf = vec![0; 2000];
            let (n, _) = recv.recv_from(&mut buf).await?;
            let msg = DnsMessage::from_slice(&buf[..n])?;

            assert_eq!(msg.response.anwsers.len(), 20);
            assert_eq!(msg.response.additional.len(), 11);

            Ok(())
        });

        sim.run()
    }
}

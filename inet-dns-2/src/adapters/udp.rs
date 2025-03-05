use bytepack::{FromBytestream, ToBytestream};
use inet::UdpSocket;
use tokio::{sync::mpsc::Sender, task::JoinHandle};

use crate::server::{
    DnsMessage, FinishedTransaction, Nameserver, NameserverQuery, TransportMedium,
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
    socket: Option<Arc<UdpSocket>>,
    handle: Option<JoinHandle<()>>,
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
        let msg = DnsMessage::response_from_transaction(anwser);
        socket.send_to(&msg.to_vec()?, target).await?;

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
        let msg = DnsMessage::request_from_ns_query(ns_query);
        socket.send_to(&msg.to_vec()?, target).await?;

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
            socket: None,
            handle: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use inet::test_util::SimpleSim;
    use serial_test::serial;

    use crate::{
        adapters::Base,
        core::{ResponseCode, ZoneResolver, Zonefile},
        server::{IterativeNameserver, RecursiveNameserver},
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
            let recu = IterativeNameserver::new(vec![zone]);
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
            let recu = IterativeNameserver::new(vec![zone]);
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
            let recu = IterativeNameserver::new(vec![zone]);
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
            let auth = IterativeNameserver::new(vec![zone]);
            let server = Base::new(auth)
                .set_root(true)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default());
            server.deploy().await
        });

        sim.node("192.168.2.20", || async move {
            let zone = ZoneResolver::new(ZONEFILE_ORG.parse()?)?;
            let auth = IterativeNameserver::new(vec![zone]);
            let server = Base::new(auth).with_adapter(TransportMedium::Udp, UdpAdapter::default());
            server.deploy().await
        });

        sim.node("192.168.2.30", || async move {
            let zone = ZoneResolver::new(ZONEFILE_EXAMPLE_ORG.parse()?)?;
            let auth = IterativeNameserver::new(vec![zone]);
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
}

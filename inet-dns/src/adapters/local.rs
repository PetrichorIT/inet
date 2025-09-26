use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use des::runtime::random;
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender},
    oneshot,
};

use crate::{
    core::{AAAAResourceRecord, AResourceRecord, DnsString},
    server::{
        DnsMessage, FinishedTransaction, Nameserver, NameserverQuery, TransactionResult,
        TransportMedium,
    },
};

use super::TransportAdapter;

/// A local transport adapter for DNS queries.
///
/// This adapter allows for queries from a local sender. Used in client resolvers
/// and the [`lookup_host`](inet::dns::lookup_host) function.
pub struct LocalAdapter {
    // caller
    rx: Option<Receiver<Request>>,
    running: Arc<Mutex<HashMap<u16, oneshot::Sender<Response>>>>,
}

type Request = (DnsString, oneshot::Sender<Response>);
type Response = io::Result<Vec<IpAddr>>;

impl LocalAdapter {
    #[must_use]
    pub fn new(rx: Receiver<Request>) -> Self {
        Self {
            rx: Some(rx),
            running: Arc::default(),
        }
    }
}

#[async_trait::async_trait]
impl TransportAdapter for LocalAdapter {
    async fn deploy(
        &mut self,
        tx: Sender<(TransportMedium, SocketAddr, DnsMessage)>,
    ) -> io::Result<()> {
        let running = self.running.clone();
        let mut rx = self.rx.take().unwrap();
        tokio::spawn(async move {
            while let Some((query, responder)) = rx.recv().await {
                let id = random::<u16>();
                running.lock().await.insert(id, responder);
                tx.send((
                    TransportMedium::Local,
                    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), id),
                    DnsMessage::question_a(id, query),
                ))
                .await
                .expect("failed");
            }
        });

        Ok(())
    }

    async fn send_anwser(&mut self, anwser: FinishedTransaction) -> io::Result<()> {
        let mut lock = self.running.lock().await;
        let Some(responder) = lock.remove(&anwser.query.transaction) else {
            return Ok(());
        };

        match anwser.result {
            TransactionResult::Success(resp) => {
                let mut addrs = Vec::new();
                for record in resp.anwsers.iter().chain(&resp.additional) {
                    if let Some(record) = record.as_any().downcast_ref::<AResourceRecord>() {
                        addrs.push(record.addr.into());
                    }
                    if let Some(record) = record.as_any().downcast_ref::<AAAAResourceRecord>() {
                        addrs.push(record.addr.into());
                    }
                }
                let _ = responder.send(Ok(addrs));
            }
            TransactionResult::Failure(err) => {
                let _ = responder.send(Err(err.into()));
            }
        }

        Ok(())
    }

    async fn send_ns_query(&mut self, _: NameserverQuery) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local device cannot send NS queries",
        ))
    }

    async fn tick(&mut self, _: &dyn Nameserver) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use inet::test_util::SimpleSim;
    use serial_test::serial;
    use tokio::sync::mpsc::channel;

    use crate::{
        adapters::{Base, UdpAdapter},
        core::{ZoneResolver, Zonefile},
        server::{IterativeNameserver, RecursiveNameserver},
    };

    use super::*;

    // const ZONEFILE_ROOT: &str = include_str!("../examples/root.zone");
    const ZONEFILE_ORG: &str = include_str!("../examples/org.zone");
    // const ZONEFILE_EXAMPLE_ORG: &str = include_str!("../examples/example.org.zone");

    #[test]
    #[serial]
    fn simple_udp_multiplex() {
        let mut sim = SimpleSim::new(inet::init);
        sim.node("192.168.2.10", || async move {
            let zone = ZoneResolver::new(ZONEFILE_ORG.parse()?)?;
            let recu = IterativeNameserver::primary(vec![zone]);
            let server = Base::new(recu).with_adapter(TransportMedium::Udp, UdpAdapter::default());
            tokio::spawn(server.deploy());

            Ok(())
        });

        sim.node_require_join("192.168.2.101", || async move {
            let rns = RecursiveNameserver::new(Zonefile::local())?
                .with_roots(vec![(Ipv4Addr::new(192, 168, 2, 10).into(), String::new())]);
            let (tx, rx) = channel(4);
            tokio::spawn(
                Base::new(rns)
                    .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                    .with_adapter(TransportMedium::Local, LocalAdapter::new(rx))
                    .deploy(),
            );

            let (rtx, rrx) = oneshot::channel();
            tx.send(("rss.info.org.".parse()?, rtx)).await.unwrap();

            assert_eq!(
                &rrx.await.unwrap().unwrap(),
                &[IpAddr::V4(Ipv4Addr::new(100, 0, 0, 2))]
            );

            Ok(())
        });

        let _ = sim.run();
    }
}

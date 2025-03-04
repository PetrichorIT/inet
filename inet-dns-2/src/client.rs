use std::{
    collections::HashMap,
    future::Future,
    io::{self, Result},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    time::Duration,
};

use bytepack::{FromBytestream, ToBytestream};
use des::{
    runtime::random,
    time::{interval_at, SimTime},
};
use inet::{extensions::with_ext, UdpSocket};
use tokio::sync::{mpsc, oneshot};

use crate::{
    adapters::DEFAULT_PORT,
    core::{AAAAResourceRecord, AResourceRecord, DnsString, QueryResponse, ResponseCode, Zonefile},
    server::{all_root_ns, DnsMessage, Nameserver, OpCode, RecursiveNameserver, TransactionResult},
};

pub fn resolve(
    host: &str,
    port: u16,
) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>>> + Send + 'static>> {
    let tx = with_ext::<DnsExtension, _>(|ext| ext.tx.as_ref().map(|tx| tx.clone()));
    let tx = tx.unwrap_or_else(|| {
        let tx = ClientResolver::default().launch();
        with_ext::<DnsExtension, _>(|ext| ext.tx = Some(tx.clone()));
        tx
    });

    let host = host.parse::<DnsString>();
    Box::pin(async move {
        let (req_tx, req_rx) = oneshot::channel();
        tx.send((host?, req_tx)).await.unwrap();

        Ok(req_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "broke pipe"))??
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    })
}

pub fn launch_client_resolver() -> RequestTx {
    ClientResolver::default().launch()
}

struct ClientResolver {
    nameserver: RecursiveNameserver,
}

#[derive(Debug, Default)]
pub struct DnsExtension {
    tx: Option<RequestTx>,
}

type RequestTx = mpsc::Sender<(DnsString, ResponderTx)>;
type RequestRx = mpsc::Receiver<(DnsString, ResponderTx)>;
type ResponderTx = oneshot::Sender<Result<Vec<IpAddr>>>;

impl ClientResolver {
    fn launch(mut self) -> RequestTx {
        tracing::trace!("launching client resolver");

        // binding the socket here, ensures that the listener is ready after this call, independent of
        // the scheduling tick of the spawned task
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Err(error) = self.run(rx).await {
                tracing::error!("client resolver crashed: {error}");
            }
        });
        tx
    }

    async fn run(&mut self, mut requests: RequestRx) -> io::Result<()> {
        let udp_socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await?;

        let mut buf = vec![0u8; 512];
        let mut interval = interval_at(SimTime::now(), Duration::from_secs(5));

        let mut mapping = HashMap::new();

        loop {
            tokio::select! {
                frame = requests.recv() => {
                    let Some((hostname, resp_tx)) = frame else { break;};

                    let id = random::<u16>();
                    mapping.insert(id, resp_tx);

                    self.nameserver.incoming(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), id), DnsMessage::question_a(id, hostname));
                }
                frame = udp_socket.recv_from(&mut buf) => {
                    let Ok((n, client)) = frame else { break };
                    let Ok(msg) = DnsMessage::read_from_slice(&mut &buf[..n]) else { continue };

                    if msg.qr {
                        self.nameserver.incoming(client, msg);
                    }
                }
                _ = interval.tick() => {}
            }

            self.nameserver.tick();

            for anwser in self.nameserver.anwsers() {
                let Some(responder) = mapping.remove(&anwser.transaction) else {
                    break;
                };

                match anwser.result {
                    TransactionResult::Success(resp) => {
                        let mut addrs = Vec::new();
                        for record in resp.anwsers.iter().chain(&resp.additional) {
                            if let Some(record) = record.as_any().downcast_ref::<AResourceRecord>()
                            {
                                addrs.push(record.addr.into());
                            }
                            if let Some(record) =
                                record.as_any().downcast_ref::<AAAAResourceRecord>()
                            {
                                addrs.push(record.addr.into());
                            }
                        }
                        let _ = responder.send(Ok(addrs));
                    }
                    TransactionResult::Failure(err) => {
                        let _ = responder.send(Err(err.into()));
                    }
                }
            }

            for query in self.nameserver.queries().collect::<Vec<_>>() {
                let msg = DnsMessage {
                    transaction: query.transaction,
                    qr: false,
                    opcode: OpCode::Query,
                    aa: false,
                    tc: false,
                    rd: true,
                    ra: false,
                    rcode: ResponseCode::NoError,
                    response: QueryResponse {
                        questions: vec![query.question],
                        ..Default::default()
                    },
                };

                if let Err(error) = udp_socket
                    .send_to(&msg.to_vec()?, (query.nameserver_ip, DEFAULT_PORT))
                    .await
                {
                    tracing::error!("cannot send query: {error}");

                    let Some(i) = self
                        .nameserver
                        .active_transactions
                        .iter()
                        .position(|p| p.local_transaction == query.transaction)
                    else {
                        continue;
                    };
                    let tx = self.nameserver.active_transactions.remove(i);
                    self.nameserver.on_query_failure(tx);
                }
            }
        }

        Ok(())
    }
}

impl Default for ClientResolver {
    fn default() -> Self {
        Self {
            nameserver: RecursiveNameserver::new(Zonefile::local())
                .expect("cannot fail")
                .with_roots(all_root_ns()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use inet::{
        dns::{lookup_host, set_dns_resolver},
        test_util::SimpleSim,
    };
    use serial_test::serial;

    use crate::{
        adapters::UdpBased,
        core::{Error, ZoneResolver},
        server::IterativeNameserver,
    };

    use super::*;

    const ZONEFILE_ROOT: &str = include_str!("examples/root.zone");
    const ZONEFILE_ORG: &str = include_str!("examples/org.zone");
    const ZONEFILE_EXAMPLE_ORG: &str = include_str!("examples/example.org.zone");

    #[test]
    #[serial]
    fn resolver_integration_with_caching() {
        let mut sim = SimpleSim::new(inet::init);

        // Servers
        sim.node("192.168.2.10", || async {
            let zf = Zonefile::from_str(ZONEFILE_ROOT)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = UdpBased::new(ns).set_root();

            server.launch().await?;
            Ok(())
        });

        sim.node("192.168.2.20", || async {
            let zf = Zonefile::from_str(ZONEFILE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = UdpBased::new(ns);

            server.launch().await?;
            Ok(())
        });

        sim.node("192.168.2.30", || async {
            let zf = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = UdpBased::new(ns);

            server.launch().await?;
            Ok(())
        });

        // Clients
        sim.node_require_join("192.168.2.101", || async {
            set_dns_resolver(resolve)?;

            let t0 = SimTime::now();
            let _ = lookup_host(("bob.example.org.", 80)).await;
            let resolve_1 = t0.elapsed();

            let t0 = SimTime::now();
            let _ = lookup_host(("bob.example.org.", 80)).await;
            let resolve_2 = t0.elapsed();

            assert_eq!(resolve_2, Duration::ZERO);

            let t0 = SimTime::now();
            let _ = lookup_host(("alice.example.org.", 80)).await;
            let resolve_3 = t0.elapsed();

            assert!(resolve_3 < resolve_1);

            tracing::info!("DONE");

            Ok(())
        });
        sim.node("192.168.2.102", || async { Ok(()) });

        let _ = sim.run();
    }

    #[test]
    #[serial]
    fn resolver_will_fail_after_timeouts() {
        let mut sim = SimpleSim::new(inet::init);

        // Servers
        sim.node("192.168.2.10", || async {
            let zf = Zonefile::from_str(ZONEFILE_ROOT)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = UdpBased::new(ns).set_root();

            server.launch().await?;
            Ok(())
        });

        sim.node("192.168.2.20", || async {
            let zf = Zonefile::from_str(ZONEFILE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = UdpBased::new(ns);

            server.launch().await?;
            Ok(())
        });

        sim.node("192.168.2.30", || async {
            let zf = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = UdpBased::new(ns);

            server.launch().await?;
            Ok(())
        });

        // Clients
        sim.node_require_join("192.168.2.101", || async {
            set_dns_resolver(resolve)?;

            let result = lookup_host(("www.subdomain.example.org.", 80)).await;
            tracing::info!("{}", result.is_err());

            if let Err(e) = result {
                assert_eq!(
                    e.downcast::<Error>().unwrap(),
                    Error::new(ResponseCode::NxDomain, "")
                )
            } else {
                panic!("there must be an error");
            }

            Ok(())
        });
        sim.node("192.168.2.102", || async { Ok(()) });

        let _ = sim.run();
    }
}

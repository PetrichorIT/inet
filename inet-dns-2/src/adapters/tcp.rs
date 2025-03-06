use crate::server::{
    DnsMessage, FinishedTransaction, Nameserver, NameserverQuery, TransportMedium,
};
use bytepack::{FromBytestream, ToBytestream};
use inet::tcp2::{OwnedWriteHalf, TcpListener, TcpStream};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::{mpsc::Sender, Mutex},
    task::JoinHandle,
};

use super::{TransportAdapter, DEFAULT_PORT};

/// A TCP transport adapter for DNS queries.
///
/// This adapter implements conventional DNS over TCP as specified in RFC 7766
pub struct TcpAdapter {
    port: u16,
    tx: Option<Sender<(TransportMedium, SocketAddr, DnsMessage)>>,

    // client managment
    query_responders: Arc<Mutex<HashMap<SocketAddr, OwnedWriteHalf>>>,
    query_handles: Arc<Mutex<HashMap<SocketAddr, JoinHandle<io::Result<()>>>>>,

    // request management
    senders: HashMap<SocketAddr, OwnedWriteHalf>,
}

#[async_trait::async_trait]
impl TransportAdapter for TcpAdapter {
    async fn deploy(
        &mut self,
        tx: Sender<(TransportMedium, SocketAddr, DnsMessage)>,
    ) -> io::Result<()> {
        self.tx = Some(tx.clone());
        let query_responders = self.query_responders.clone();
        let query_handles = self.query_handles.clone();

        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), self.port);
        tokio::spawn(async move {
            let listener = TcpListener::bind(addr).await?;
            while let Ok((stream, from)) = listener.accept().await {
                let (read, write) = stream.into_split();

                query_responders.lock().await.insert(from, write);
                let handle = tokio::spawn(dispatch_incoming_events_from(tx.clone(), from, read));
                query_handles.lock().await.insert(from, handle);
            }

            Ok::<(), io::Error>(())
        });

        Ok(())
    }

    async fn send_anwser(&mut self, tx: FinishedTransaction) -> io::Result<()> {
        let mut lock = self.query_responders.lock().await;
        let Some(responder) = lock.get_mut(&tx.query.addr) else {
            tracing::error!("could not find responder for tx fin: {tx:?}");
            return Ok(());
        };

        let msg = DnsMessage::response_from_transaction(tx);
        responder.write_all(&msg.to_vec()?).await?;

        Ok(())
    }

    async fn send_ns_query(&mut self, ns_query: NameserverQuery) -> io::Result<()> {
        let nsaddr = SocketAddr::new(ns_query.nameserver_ip, DEFAULT_PORT);
        let write = match self.senders.get_mut(&nsaddr) {
            Some(write) => write,
            None => {
                let stream = TcpStream::connect(nsaddr).await?;
                let (read, write) = stream.into_split();

                tokio::spawn(dispatch_incoming_events_from(
                    self.tx.as_ref().unwrap().clone(),
                    nsaddr,
                    read,
                ));

                self.senders.insert(nsaddr, write);
                self.senders.get_mut(&nsaddr).expect("unreachable")
            }
        };

        let msg = DnsMessage::request_from_ns_query(ns_query);
        write.write_all(&msg.to_vec()?).await?;

        Ok(())
    }

    fn tick<'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        nameserver: &'life1 dyn Nameserver,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let active = nameserver.active_queries();
        Box::pin(async move {
            let mut query_responders = self.query_responders.lock().await;
            let mut query_handles = self.query_handles.lock().await;

            query_handles.retain(|addr, handle| {
                let retain = !handle.is_finished();
                if !retain {
                    tracing::trace!("removing client connection {addr}");
                    query_responders.remove(addr);
                }
                retain
            });

            self.senders.retain(|addr, _| {
                // There is some connection currently using this ns query
                let retain = active.iter().any(|query| query.nameserver_ip == addr.ip());
                if !retain {
                    tracing::info!("removing server connection {addr}");
                }
                retain
            });
            Ok(())
        })
    }
}

impl Default for TcpAdapter {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            tx: None,
            query_responders: Arc::default(),
            query_handles: Arc::default(),
            senders: HashMap::default(),
        }
    }
}

#[tracing::instrument(name = "con", skip(tx, stream))]
async fn dispatch_incoming_events_from<R: AsyncRead + Unpin>(
    tx: Sender<(TransportMedium, SocketAddr, DnsMessage)>,
    peer: SocketAddr,
    mut stream: R,
) -> io::Result<()> {
    let mut buf = Vec::new();
    loop {
        let n = match stream.read_buf(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("socket error: {e}");
                return Err(e);
            }
        };

        tracing::trace!("connection queuing {n} bytes");

        while !buf.is_empty() {
            match DnsMessage::read_from_vec(&mut buf) {
                Ok(msg) => {
                    // consumed the bytes from the buf, msg no ready
                    tx.send((TransportMedium::Tcp, peer, msg))
                        .await
                        .expect("msg tx failed: dns server must have failed, failing too");
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // buffer might not be full enough for a full packet
                    break;
                }
                Err(e) => {
                    // invalid packet, try to get rid of all data
                    tracing::error!("connection contained unknown error: {e}");
                    buf.clear();
                }
            }
        }

        // if connection is closing, end the receiving
        if n == 0 {
            tracing::trace!("ending recv on connection {peer}");
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use inet::test_util::SimpleSim;
    use serial_test::serial;

    use crate::{
        adapters::Base,
        core::{DnsString, ZoneResolver, Zonefile},
        server::{IterativeNameserver, RecursiveNameserver},
    };

    use super::*;

    const ZONEFILE_ROOT: &str = include_str!("../examples/root.zone");
    const ZONEFILE_ORG: &str = include_str!("../examples/org.zone");
    const ZONEFILE_EXAMPLE_ORG: &str = include_str!("../examples/example.org.zone");

    #[test]
    #[serial]
    fn simple_anwser() {
        let mut sim = SimpleSim::new(inet::init);

        sim.node("192.168.2.30", || async {
            let zf = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);
            let server = Base::new(ns).with_adapter(TransportMedium::Tcp, TcpAdapter::default());

            server.deploy().await?;
            Ok(())
        });

        // Clients
        sim.node_require_join("192.168.2.101", || async {
            let mut socket = TcpStream::connect(("192.168.2.30", DEFAULT_PORT)).await?;
            let msg = DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?);
            socket.write_all(&msg.to_vec()?).await?;

            let mut buf = vec![0; 512];
            let n = socket.read(&mut buf).await?;

            let msg = DnsMessage::from_slice(&buf[..n])?;
            assert_eq!(msg.response.anwsers.len(), 1);

            drop(socket);

            Ok(())
        });

        let _ = sim.run_max_time(5.0);
    }

    #[test]
    #[serial]
    fn recursive_query() {
        let mut sim = SimpleSim::new(inet::init);

        sim.node("192.168.2.10", || async {
            let zf = Zonefile::from_str(ZONEFILE_ROOT)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);
            Base::new(ns)
                .with_adapter(TransportMedium::Tcp, TcpAdapter::default())
                .deploy()
                .await
        });

        sim.node("192.168.2.20", || async {
            let zf = Zonefile::from_str(ZONEFILE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);
            Base::new(ns)
                .with_adapter(TransportMedium::Tcp, TcpAdapter::default())
                .deploy()
                .await
        });

        // REsolver
        sim.node("192.168.2.100", || async {
            let ns = RecursiveNameserver::new(Zonefile::local())?
                .with_roots(vec![(Ipv4Addr::new(192, 168, 2, 10).into(), String::new())]);
            Base::new(ns)
                .with_adapter(TransportMedium::Tcp, TcpAdapter::default())
                .deploy()
                .await
        });

        // Clients
        sim.node_require_join("192.168.2.101", || async {
            let mut socket = TcpStream::connect(("192.168.2.100", DEFAULT_PORT)).await?;
            let msg = DnsMessage::question_a(1, "rss.info.org.".parse::<DnsString>()?);
            socket.write_all(&msg.to_vec()?).await?;

            let mut buf = vec![0; 512];
            let n = socket.read(&mut buf).await?;

            let msg = DnsMessage::from_slice(&buf[..n])?;
            assert_eq!(msg.response.anwsers.len(), 1);

            tracing::info!("test completed");
            drop(socket);

            Ok(())
        });

        let _ = sim.run_max_time(5.0);
    }
}

use crate::{
    core::{QueryResponse, ResponseCode},
    server::{declare_root, DnsMessage, Nameserver, OpCode},
};
use bytepack::{FromBytestream, ToBytestream};
use des::time::interval;
use inet::{
    tcp2::{TcpListener, TcpStream},
    utils::get_ip,
};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::mpsc::{channel, Sender},
};

use super::DEFAULT_PORT;

pub struct TcpBased<T: Nameserver> {
    nameserver: T,
    port: u16,
    root: bool,
}

impl<T: Nameserver> TcpBased<T> {
    pub fn new(nameserver: T) -> Self {
        TcpBased {
            nameserver,
            port: DEFAULT_PORT,
            root: false,
        }
    }

    pub const fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn set_root(mut self) -> Self {
        self.root = true;
        self
    }

    pub async fn launch(&mut self) -> io::Result<()> {
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), self.port);
        let listener = TcpListener::bind(addr).await?;

        tracing::trace!(
            "created socket {} for dns requrests",
            listener.local_addr()?
        );
        if self.root {
            declare_root(get_ip().unwrap(), ".".to_string());
        }

        let mut readers = HashMap::new();
        let mut responders = HashMap::new();

        let mut querying = HashMap::new();

        let (tx, mut rx) = channel(8);
        let mut interval = interval(Duration::from_secs(2));

        loop {
            tokio::select! {
                frame = rx.recv() => {
                    let (from, msg) = frame.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "broke pipe"))?;
                    self.nameserver.incoming(from, msg);
                }

                frame = listener.accept() => {
                    let (stream, from) = frame?;
                    let (read, write) = stream.into_split();
                    let read_handle = tokio::spawn(dispatch_incoming_from(
                        tx.clone(),
                        from,
                        read,
                    ));
                    readers.insert(from, read_handle);
                    responders.insert(from, write);
                }
                _ = interval.tick() => {}
            }

            self.nameserver.tick();

            for anwser in self.nameserver.anwsers() {
                // close tcp connection
                let Some(responder) = responders.get_mut(&anwser.client) else {
                    tracing::error!("could not find responder for tx fin: {anwser:?}");
                    continue;
                };

                tracing::info!("responding to {} with:{}", anwser.client, anwser.result);

                let msg = DnsMessage::response_from_transaction(anwser);
                responder.write_all(&msg.to_vec()?).await?;
            }

            for query in self.nameserver.queries() {
                let addr = SocketAddr::new(query.nameserver_ip, DEFAULT_PORT);

                let write = match querying.get_mut(&addr) {
                    Some(write) => write,
                    None => {
                        let socket = TcpStream::connect(addr).await?;

                        let (read, write) = socket.into_split();
                        tokio::spawn(dispatch_incoming_from(tx.clone(), addr, read));

                        querying.insert(addr, write);
                        querying.get_mut(&addr).expect("unreachable")
                    }
                };

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
                write.write_all(&msg.to_vec()?).await?;
            }

            // Close connections towards clients (we act as the server)
            readers.retain(|addr, handle| {
                let retain = !handle.is_finished();
                if !retain {
                    tracing::info!("removing client connection {addr}");
                    responders.remove(addr);
                }
                retain
            });

            // Close connection towards other servers (we act as a client)
            let active = self.nameserver.active_queries().collect::<Vec<_>>();
            querying.retain(|addr, _| {
                // There is some connection currently using this ns query
                let retain = active.iter().any(|query| query.nameserver_ip == addr.ip());
                if !retain {
                    tracing::info!("removing server connection {addr}");
                }
                retain
            })
        }
    }
}

#[tracing::instrument(name = "con", skip(tx, stream))]
async fn dispatch_incoming_from<R: AsyncRead + Unpin>(
    tx: Sender<(SocketAddr, DnsMessage)>,
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
                    tx.send((peer, msg))
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
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = TcpBased::new(ns);

            server.launch().await?;
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
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = TcpBased::new(ns);

            server.launch().await?;
            Ok(())
        });

        sim.node("192.168.2.20", || async {
            let zf = Zonefile::from_str(ZONEFILE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::new(vec![zone]);
            let mut server = TcpBased::new(ns);

            server.launch().await?;
            Ok(())
        });

        // REsolver
        sim.node("192.168.2.100", || async {
            let ns = RecursiveNameserver::new(Zonefile::local())?
                .with_roots(vec![(Ipv4Addr::new(192, 168, 2, 10).into(), String::new())]);
            let mut server = TcpBased::new(ns);

            server.launch().await?;
            Ok(())
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

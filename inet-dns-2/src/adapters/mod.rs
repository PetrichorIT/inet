use std::{collections::HashMap, io, net::SocketAddr, time::Duration};

use des::time::interval;
use inet::utils::get_ip;
use tokio::sync::mpsc::{channel, Sender};

use crate::server::{
    declare_root, DnsMessage, FinishedTransaction, Nameserver, NameserverQuery, TransportMedium,
};

mod local;
mod tcp;
mod udp;

pub use local::LocalAdapter;
pub use tcp::TcpAdapter;
pub use udp::UdpAdapter;

pub const DEFAULT_PORT: u16 = 53;

pub struct Base<T: Nameserver> {
    nameserver: T,
    adapters: HashMap<TransportMedium, Box<dyn TransportAdapter>>,
    root: bool,
}

impl<T: Nameserver> Base<T> {
    pub fn new(nameserver: T) -> Self {
        Self {
            nameserver,
            adapters: HashMap::new(),
            root: false,
        }
    }

    pub fn set_root(mut self, root: bool) -> Self {
        self.root = root;
        self
    }

    pub fn with_adapter(mut self, medium: TransportMedium, adapter: impl TransportAdapter) -> Self {
        self.adapters.insert(medium, Box::new(adapter));
        self
    }

    pub async fn deploy(mut self) -> io::Result<()> {
        if self.root {
            declare_root(
                get_ip().ok_or(io::Error::new(
                    io::ErrorKind::NetworkDown,
                    "no ip addr available",
                ))?,
                ".".to_string(),
            );
        }

        let (tx, mut rx) = channel(8);
        let mut interval = interval(Duration::from_secs(2));

        for adapter in self.adapters.values_mut() {
            adapter.deploy(tx.clone()).await?;
        }

        loop {
            tokio::select! {
                event = rx.recv() => {
                    let (medium, from, msg) = event.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "broke pipe"))?;
                    self.nameserver.incoming(medium, from, msg);
                }
                _ = interval.tick() => {}
            };

            self.nameserver.tick();
            for adapter in self.adapters.values_mut() {
                adapter.tick(&self.nameserver).await?;
            }

            for anwser in self.nameserver.anwsers() {
                let Some(adapter) = self.adapters.get_mut(&anwser.query.medium) else {
                    continue;
                };
                adapter.send_anwser(anwser).await?;
            }

            for ns_query in self.nameserver.ns_queries() {
                let mut medium = ns_query.query.medium;
                loop {
                    tracing::info!("{medium:?}");
                    let Some(adapter) = self.adapters.get_mut(&medium) else {
                        break;
                    };
                    match adapter.send_ns_query(ns_query.clone()).await {
                        Ok(()) => break,
                        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                            if let Some(new_medium) = medium.fallback() {
                                medium = new_medium;
                            } else {
                                tracing::error!("no fallback medium available: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::error!("{e}");
                            break;
                        }
                    };
                }
            }
        }
    }
}

#[async_trait::async_trait]
pub trait TransportAdapter: Send + 'static {
    async fn deploy(
        &mut self,
        tx: Sender<(TransportMedium, SocketAddr, DnsMessage)>,
    ) -> io::Result<()>;
    async fn send_anwser(&mut self, tx: FinishedTransaction) -> io::Result<()>;
    async fn send_ns_query(&mut self, ns_query: NameserverQuery) -> io::Result<()>;
    async fn tick(&mut self, nameserver: &dyn Nameserver) -> io::Result<()>;
}

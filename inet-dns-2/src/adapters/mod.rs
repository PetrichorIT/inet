//! Adapters for connecting DNS nameserver to communication resources

use std::{cmp::Reverse, collections::HashMap, io, net::SocketAddr, time::Duration};

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

/// The base wrapper for deploying DNS nameservers with various adapters.
///
/// Use this type, to connect an arbitrary DNS nameserver with transport layer adapters. The
/// following adapters are available:
///
/// - [`LocalAdapter`]: A local adapter that anwsers queries supplied by a [`channel`].
///                     Used by the client resolver.
/// - [`TcpAdapter`]: A TCP adapter that listens on the specified port.
/// - [`UdpAdapter`]: A UDP adapter that listens on the specified port.
///
/// # Examples
///
/// ```rust
/// # use std::io;
/// # use inet_dns_2::adapters::{Base, LocalAdapter, TcpAdapter, UdpAdapter};
/// # use inet_dns_2::server::{TransportMedium, RecursiveNameserver};
/// async fn alice() -> io::Result<()> {
///     let nameserver: RecursiveNameserver = todo!();
///     let base = Base::new(nameserver).with_adapter(TransportMedium::Udp, UdpAdapter::default());
///     base.deploy().await
/// }
/// ```
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

    /// Sets the root flag, indicating that this DNS server can be used as a root server.
    pub fn set_root(mut self, root: bool) -> Self {
        self.root = root;
        self
    }

    /// Adds an adapter for the given transport medium.
    ///
    /// There can only be one adapter per transport medium.
    pub fn with_adapter(mut self, medium: TransportMedium, adapter: impl TransportAdapter) -> Self {
        self.adapters.insert(medium, Box::new(adapter));
        self
    }

    /// Deploys the DNS server, starting the necessary adapters and declaring the root server if applicable.
    ///
    /// This method should be called after all adapters have been added.
    /// Note that this function will block forever, waiting for incoming requests. Use
    /// `tokio::spawn` to run it in a separate task if necessary.
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

        let mut available_media = self.adapters.keys().copied().collect::<Vec<_>>();
        available_media.sort_by_key(|v| *v as usize);

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
                if let Some(preferred) = ns_query.preferred {
                    available_media.sort_by_key(|k| Reverse(*k == preferred));
                }

                for medium in &available_media {
                    let Some(adapter) = self.adapters.get_mut(medium) else {
                        break;
                    };
                    match adapter.send_ns_query(ns_query.clone()).await {
                        Ok(()) => break,
                        Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
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

/// This trait defines the interface for all transport adapters.
///
/// Transport adapters are used to send and receive DNS messages over a specific transport medium.
/// They are responsible for handling the low-level details of the transport protocol, such as
/// establishing connections, sending and receiving packets, and handling errors.
#[async_trait::async_trait]
pub trait TransportAdapter: Send + 'static {
    /// Deploy the transport adapter.
    ///
    /// This method is called when the transport adapter is first created and is responsible for
    /// initializing any necessary resources, such as opening a socket or establishing a connection.
    async fn deploy(
        &mut self,
        tx: Sender<(TransportMedium, SocketAddr, DnsMessage)>,
    ) -> io::Result<()>;

    /// Send a DNS response to the specified address.
    ///
    /// This method is called when a DNS message needs to be sent to a specific address.
    /// When called, it can be assumed that a DNS request has already been received from
    /// this address on the same transport medium.
    async fn send_anwser(&mut self, tx: FinishedTransaction) -> io::Result<()>;

    /// Send a DNS query to the specified nameserver.
    ///
    /// This method is called when a DNS query needs to be sent to a specific nameserver.
    /// Multiple queries may be directed to the same nameserver. If applicable, the transport
    /// adapter should handle the necessary load balancing and failover mechanisms.
    async fn send_ns_query(&mut self, ns_query: NameserverQuery) -> io::Result<()>;

    /// This method is called periodically to perform any necessary maintenance tasks.
    async fn tick(&mut self, nameserver: &dyn Nameserver) -> io::Result<()>;
}

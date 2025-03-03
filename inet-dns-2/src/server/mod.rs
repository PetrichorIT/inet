use bytepack::{FromBytestream, ToBytestream};
use des::time::sleep;
use inet::{utils::get_ip, UdpSocket};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

mod iterative;
mod pkt;
mod recursive;
mod root;
mod transaction;
mod types;

use crate::core::QueryResponse;
pub use iterative::IterativeNameserver;
pub use pkt::*;
pub use recursive::RecursiveNameserver;
pub use root::*;
pub use transaction::{ActiveTransaction, FinishedTransaction, TransactionResult};
use types::NameserverQuery;

use super::core::ResponseCode;

pub trait Nameserver {
    fn incoming(&mut self, source: SocketAddr, msg: DnsMessage);
    fn queries(&mut self) -> impl Iterator<Item = NameserverQuery>;
    fn anwsers(&mut self) -> impl Iterator<Item = FinishedTransaction>;
}

pub struct UdpBased<T: Nameserver> {
    nameserver: T,
    port: u16,
    root: bool,
}

impl<T: Nameserver> UdpBased<T> {
    pub const fn new(nameserver: T) -> Self {
        Self {
            nameserver,
            port: 43,
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
        let socket = UdpSocket::bind(addr).await?;

        tracing::trace!("created socket {} for dns requrests", socket.local_addr()?);
        if self.root {
            declare_root(get_ip().unwrap(), ".".to_string());
        }

        let mut buf = vec![0u8; 512];
        loop {
            let timeout = sleep(Duration::from_secs(5));

            // Wait for incoming streams
            tokio::select! {
                frame = socket.recv_from(&mut buf) => {
                    let Ok((n, client)) = frame else { break };
                    let Ok(msg) = DnsMessage::read_from_slice(&mut &buf[..n]) else { continue };

                    self.nameserver.incoming(client, msg);
                }
                _ = timeout => {}
            }

            // Process outgoing streams
            for anwser in self.nameserver.anwsers() {
                let target = anwser.client;
                let msg = DnsMessage::response_from_transaction(anwser);
                socket.send_to(&msg.to_vec()?, target).await?;
            }

            for query in self.nameserver.queries() {
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

                socket
                    .send_to(&msg.to_vec()?, (query.nameserver_ip, 43))
                    .await?;
            }
        }

        tracing::trace!("closed socket {} for dns requrests", socket.local_addr()?);

        Ok(())
    }
}

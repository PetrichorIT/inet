use bytepack::{FromBytestream, ToBytestream};
use des::time::sleep;
use inet::UdpSocket;
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
pub use iterative::DnsIterativeNameserver;
pub use pkt::*;
pub use recursive::DnsRecursiveNameserver;
use transaction::DnsFinishedTransaction;
use types::DnsNameserverQuery;

use super::core::DnsResponseCode;

pub trait DnsNameserver {
    fn incoming(&mut self, source: SocketAddr, msg: DnsMessage);
    fn queries(&mut self) -> impl Iterator<Item = DnsNameserverQuery>;
    fn anwsers(&mut self) -> impl Iterator<Item = DnsFinishedTransaction>;
}

pub struct UdpBased<T: DnsNameserver> {
    nameserver: T,
}

impl<T: DnsNameserver> UdpBased<T> {
    pub async fn launch(&mut self) -> io::Result<()> {
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 43);
        let socket = UdpSocket::bind(addr).await?;

        tracing::info!("created socket {} for dns requrests", socket.local_addr()?);

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
                // let buf = anwser.
                dbg!(anwser);
            }

            for query in self.nameserver.queries() {
                let msg = DnsMessage {
                    transaction: query.transaction,
                    qr: false,
                    opcode: DnsOpCode::Query,
                    aa: false,
                    tc: false,
                    rd: true,
                    ra: false,
                    rcode: DnsResponseCode::NoError,
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

        tracing::info!("closed socket {} for dns requrests", socket.local_addr()?);

        Ok(())
    }
}

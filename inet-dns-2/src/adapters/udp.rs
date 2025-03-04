use bytepack::{FromBytestream, ToBytestream};
use des::time::sleep;
use inet::{utils::get_ip, UdpSocket};

use crate::{
    core::{QueryResponse, ResponseCode},
    server::{declare_root, DnsMessage, Nameserver, OpCode},
};

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use super::DEFAULT_PORT;

pub struct UdpBased<T: Nameserver> {
    nameserver: T,
    port: u16,
    root: bool,
}

impl<T: Nameserver> UdpBased<T> {
    pub const fn new(nameserver: T) -> Self {
        Self {
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

            self.nameserver.tick();

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
                    .send_to(&msg.to_vec()?, (query.nameserver_ip, DEFAULT_PORT))
                    .await?;
            }
        }

        tracing::trace!("closed socket {} for dns requrests", socket.local_addr()?);

        Ok(())
    }
}

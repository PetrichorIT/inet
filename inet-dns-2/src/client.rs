use std::{
    future::Future,
    io::{self, Result},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    time::Duration,
};

use bytepack::{FromBytestream, ToBytestream};
use des::time::{interval_at, SimTime};
use inet::UdpSocket;

use crate::{
    core::{
        AAAAResourceRecord, AResourceRecord, DnsQuestion, DnsResponseCode, DnsString,
        QueryResponse, QuestionClass, QuestionTyp, Zonefile,
    },
    server::{all_root_ns, DnsMessage, DnsNameserver, DnsOpCode, DnsRecursiveNameserver},
};

pub fn dns_resolver(
    host: &str,
    port: u16,
) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>>> + Send + '_>> {
    Box::pin(async move {
        // TODO: store the resolver, to preserve caching
        let mut cr = ClientResolver::default();
        let result = cr.query(host, port).await;
        result
    })
}

pub struct ClientResolver {
    nameserver: DnsRecursiveNameserver,
}

impl ClientResolver {
    pub async fn query(&mut self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        let socket = UdpSocket::bind(addr).await?;

        tracing::trace!("created socket {} for dns requrests", socket.local_addr()?);

        let mut qname = host.parse::<DnsString>()?;
        if qname.is_relative() {
            qname = qname.with_root(&DnsString::empty());
        }

        self.nameserver.handle_query(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            0,
            DnsQuestion {
                qname: qname.clone(),
                qtyp: QuestionTyp::A,
                qclass: QuestionClass::IN,
            },
        );

        let mut addrs = Vec::new();
        let mut interval = interval_at(SimTime::now(), Duration::from_secs(5));

        let mut buf = vec![0u8; 512];
        while !self.nameserver.active_transactions.is_empty() {
            let timeout = interval.tick();

            // Wait for incoming streams
            tokio::select! {
                frame = socket.recv_from(&mut buf) => {
                    let Ok((n, client)) = frame else { break };
                    let Ok(msg) = DnsMessage::read_from_slice(&mut &buf[..n]) else { continue };

                    if msg.qr {
                        self.nameserver.incoming(client, msg);
                    }
                }
                _ = timeout => {}
            }

            // Process outgoing streams
            for anwser in self.nameserver.anwsers() {
                // let buf = anwser.
                for anwser in anwser
                    .response
                    .anwsers
                    .iter()
                    .chain(&anwser.response.additional)
                {
                    if let Some(record) = anwser.as_any().downcast_ref::<AResourceRecord>() {
                        addrs.push(SocketAddr::V4(SocketAddrV4::new(record.addr, port)));
                    }
                    if let Some(record) = anwser.as_any().downcast_ref::<AAAAResourceRecord>() {
                        addrs.push(SocketAddr::V6(SocketAddrV6::new(record.addr, port, 0, 0)));
                    }
                }
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

        tracing::trace!("closed socket {} for dns requrests", socket.local_addr()?);

        addrs.dedup();
        Ok(addrs)
    }
}

impl Default for ClientResolver {
    fn default() -> Self {
        Self {
            nameserver: DnsRecursiveNameserver::new(Zonefile::local())
                .expect("cannot fail")
                .with_roots(all_root_ns()),
        }
    }
}

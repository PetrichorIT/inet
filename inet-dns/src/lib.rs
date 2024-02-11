use bytepack::{FromBytestream, ToBytestream};
use des::time::sleep;
use inet::UdpSocket;
use std::future::Future;
use std::io::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;
use tokio::select;
use types::DNSMessage;

#[macro_use]
mod macros;

mod nameserver;
pub use nameserver::*;

mod zonefile;
pub use zonefile::DNSZoneFile;

pub mod types;
use types::{DNSResponseCode, DNSType};

pub fn real_dns_resolver(
    host: &str,
    port: u16,
) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>>> + Send>> {
    let host = host.to_string();
    Box::pin(async move {
        // Real resolve
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let mut question = DNSMessage::question_a(0x01, host);
        question.rd = true;
        let buf = question.to_vec()?;

        let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
        let n = socket.send_to(&buf, localhost).await?;

        if n != buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "could not send dns query",
            ));
        }

        loop {
            let mut buf = vec![0u8; 512];
            let n = select! {
                result = socket.recv_from(&mut buf) => {
                    result?.0
                },
                _ = sleep(Duration::new(5, 0)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "failed to lookup address information: request timed out"
                    ))
                }
            };
            buf.truncate(n);

            let mut response = DNSMessage::read_from_vec(&mut buf)?;
            assert!(response.qr);

            if response.rcode != DNSResponseCode::NoError {
                match response.rcode {
                    DNSResponseCode::NxDomain => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "failed to lookup address information: nodename nor servname provided, or not known"
                    )),
                    DNSResponseCode::ServFail => return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "failed to lookup address information: dns resolver failed"
                    )),
                    _ => unimplemented!()
                }
            }

            if !response.anwsers.is_empty() {
                let mut vec = Vec::with_capacity(response.additional.len() + 1);
                let addr = response.anwsers.remove(0).as_addr();
                vec.push(SocketAddr::new(addr, port));

                for additional in response.additional {
                    if additional.typ != DNSType::A && additional.typ != DNSType::AAAA {
                        continue;
                    }
                    let addr = additional.as_addr();
                    vec.push(SocketAddr::new(addr, port));
                }
                return Ok(vec);
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Iterative resolve not supported yet",
                ));
            }
        }
    })
}

use bytepack::ToBytestream;
use des::prelude::*;
use inet_types::icmp::{IcmpPacket, IcmpType, PROTO_ICMP};
use inet_types::ip::{IpPacket, Ipv4Flags, Ipv4Packet};
use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::oneshot;

use crate::socket::SocketIfaceBinding;
use crate::IOContext;

pub(super) struct PingCB {
    pub addr: Ipv4Addr,
    pub values: Vec<Duration>,
    pub identifier: u16,
    pub current_seq_no: u16,
    pub current_send_time: SimTime,
    pub limit: usize,

    pub publish: Option<oneshot::Sender<Result<Ping>>>,
}

/// The result of a call to `ping`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ping {
    /// The received time-to-live (TTL) of
    /// returing ICMP Echo Replys
    pub ttl: u32,
    /// The fastest measured round-trip-time (RTT).
    pub time_min: Duration,
    /// The slowes measured round-trip-time (RTT).
    pub time_max: Duration,
    /// The average round-trip-time (RTT).
    pub time_avg: Duration,
}

/// Tries to determine reachability and round-trip time
/// to a specified target
pub async fn ping(addr: impl Into<Ipv4Addr>) -> Result<Ping> {
    ping_with(addr, 3).await
}

/// Tries to determine reachability and round-trip time
/// to a specified target
///
/// This function takes the number of samples as an extra paramter.
/// The default value used by `ping` is 3.
pub async fn ping_with(addr: impl Into<Ipv4Addr>, c: usize) -> Result<Ping> {
    let addr = addr.into();
    let rx = IOContext::failable_api(|ctx| ctx.icmp_initiate_ping(addr, c))?;
    rx.await
        .map_err(|_| Error::new(ErrorKind::Other, "broke pipe"))?
}

impl IOContext {
    fn icmp_initiate_ping(
        &mut self,
        addr: Ipv4Addr,
        c: usize,
    ) -> Result<oneshot::Receiver<Result<Ping>>> {
        let (tx, rx) = oneshot::channel();
        let identifier = random();
        self.icmp.pings.insert(
            identifier,
            PingCB {
                addr,
                identifier,
                values: Vec::with_capacity(c),
                current_seq_no: 0,
                current_send_time: SimTime::now(),
                limit: c,
                publish: Some(tx),
            },
        );

        self.icmp_send_ping(addr, identifier, 0);
        Ok(rx)
    }

    pub(super) fn icmp_send_ping(&mut self, addr: Ipv4Addr, identifier: u16, sequence: u16) {
        let mut ip = Ipv4Packet {
            enc: 0,
            dscp: 0,
            identification: 0,
            flags: Ipv4Flags {
                df: true,
                mf: false,
            },
            fragment_offset: 0,
            ttl: 32,
            proto: PROTO_ICMP,
            src: Ipv4Addr::UNSPECIFIED,
            dest: addr,
            content: vec![0; 36],
        };
        let icmp = IcmpPacket::new(
            IcmpType::EchoRequest {
                identifier,
                sequence,
            },
            &ip,
        );
        ip.content = icmp.to_buffer().expect("Failed to parse ICMP");

        self.send_ip_packet(
            SocketIfaceBinding::Any(self.ifaces.keys().copied().collect::<Vec<_>>()),
            IpPacket::V4(ip),
            true,
        )
        .expect("Failed to send");
    }
}

impl PingCB {
    pub(super) fn recv_echo_reply(&mut self, identifer: u16, sequence: u16) -> bool {
        // Check Seq NO;
        assert_eq!(self.identifier, identifer);
        assert_eq!(self.current_seq_no, sequence);

        let dur = SimTime::now() - self.current_send_time;
        self.values.push(dur);

        if self.values.len() >= self.limit {
            // Done
            let mut min = Duration::MAX;
            let mut max = Duration::ZERO;
            let mut acc = Duration::ZERO;
            for &value in &self.values {
                if value < min {
                    min = value;
                }
                if value > max {
                    max = value
                }
                acc += value;
            }
            let time_avg = Duration::from_secs_f64(acc.as_secs_f64() / self.values.len() as f64);
            let ping = Ping {
                ttl: 0,
                time_min: min,
                time_max: max,
                time_avg,
            };
            self.publish.take().map(|s| s.send(Ok(ping)));

            false
        } else {
            // MOre
            true
        }
    }
}

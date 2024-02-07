use crate::{ctx::IOContext, interface::IfId};
use bytepack::ToBytestream;
use des::time::SimTime;
use inet_types::{
    icmpv6::{IcmpV6Echo, IcmpV6Packet, PROTO_ICMPV6},
    ip::Ipv6Packet,
};
use std::{fmt, io, iter, net::Ipv6Addr, time::Duration};
use tokio::sync::oneshot;

/// Tries to determine reachability and round-trip time
/// to a specified target
pub async fn ping(addr: impl Into<Ipv6Addr>) -> io::Result<Ping> {
    ping_with(addr, 3).await
}

/// Tries to determine reachability and round-trip time
/// to a specified target
///
/// This function takes the number of samples as an extra paramter.
/// The default value used by `ping` is 3.
pub async fn ping_with(addr: impl Into<Ipv6Addr>, c: usize) -> io::Result<Ping> {
    let addr = addr.into();
    let rx = IOContext::failable_api(|ctx| ctx.ipv6_icmp_initate_ping(addr, c))?;
    rx.await
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "broke pipe"))?
}

#[allow(dead_code)]
pub struct PingCtrl {
    pub addr: Ipv6Addr,
    values: Vec<Duration>,
    identifier: u16,
    cur_seq_no: u16,
    cur_send_time: SimTime,
    limit: usize,

    publish: Option<oneshot::Sender<io::Result<Ping>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    pub addr: Ipv6Addr,
    pub ttl: u8,
    pub time_min: Duration,
    pub time_max: Duration,
    pub time_avg: Duration,
}

impl PingCtrl {
    pub fn process(&mut self, echo: IcmpV6Echo) -> Option<IcmpV6Packet> {
        // Check Seq NO;
        assert_eq!(self.identifier, echo.identifier);
        assert_eq!(self.cur_seq_no, echo.sequence_no);

        let dur = SimTime::now() - self.cur_send_time;
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
                addr: self.addr,
                ttl: 0,
                time_min: min,
                time_max: max,
                time_avg,
            };
            self.publish.take().map(|s| s.send(Ok(ping)));
            None
        } else {
            self.cur_seq_no += 1;
            Some(IcmpV6Packet::EchoRequest(IcmpV6Echo {
                identifier: self.identifier,
                sequence_no: self.cur_seq_no,
                data: random_bytes(52),
            }))
        }
    }

    pub fn fail_with_error(&mut self, error: io::Error) {
        let Some(tx) = self.publish.take() else {
            return;
        };
        // If an error occures rx does not exist anymore, so
        // reporting the error is no longer nessecary.
        // Accordingly ignore the error
        let _ = tx.send(Err(error));
    }
}

impl IOContext {
    fn ipv6_icmp_initate_ping(
        &mut self,
        addr: Ipv6Addr,
        c: usize,
    ) -> io::Result<oneshot::Receiver<io::Result<Ping>>> {
        let (tx, rx) = oneshot::channel();
        let identifier = des::runtime::random();
        self.ipv6.ping_ctrl.insert(
            identifier,
            PingCtrl {
                addr,
                identifier,
                values: Vec::with_capacity(c),
                cur_seq_no: 0,
                cur_send_time: SimTime::now(),
                limit: c,
                publish: Some(tx),
            },
        );

        self.ipv6_icmp_send_ping(addr, identifier, 0)?;
        Ok(rx)
    }

    fn ipv6_icmp_send_ping(
        &mut self,
        addr: Ipv6Addr,
        identifier: u16,
        sequence_no: u16,
    ) -> io::Result<()> {
        let msg = IcmpV6Echo {
            identifier,
            sequence_no,
            data: random_bytes(52),
        };
        let msg = IcmpV6Packet::EchoRequest(msg);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            hop_limit: 64,
            next_header: PROTO_ICMPV6,
            src: Ipv6Addr::UNSPECIFIED,
            dst: addr,
            content: msg.to_vec()?,
        };

        self.ipv6_send(pkt, IfId::NULL)
    }
}

impl fmt::Display for Ping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:?}/{:?}/{:?} ttl {}",
            self.addr, self.time_min, self.time_avg, self.time_max, self.ttl
        )
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    iter::repeat_with(des::runtime::random::<u8>)
        .take(n)
        .collect()
}

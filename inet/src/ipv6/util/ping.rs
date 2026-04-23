use std::{fmt, io, net::Ipv6Addr, time::Duration};

use bytes_io::{Bytes, FromBytes, ToBytes};
use des::time::{SimTime, sleep_until};
use types::icmpv6::{IcmpV6Echo, IcmpV6Packet, PROTO_ICMPV6};

use crate::{ipv6::socket::RawV6Socket, socket::AsRawFd};

#[derive(Debug, Clone, PartialEq)]
pub struct Ping {
    pub addr: Ipv6Addr,
    pub loss: f64,
    pub time_min: Duration,
    pub time_max: Duration,
    pub time_avg: Duration,
}

impl fmt::Display for Ping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:?}/{:?}/{:?} loss {}",
            self.addr, self.time_min, self.time_avg, self.time_max, self.loss
        )
    }
}

pub async fn ping(addr: Ipv6Addr) -> io::Result<Ping> {
    ping_with(addr, 3).await
}

pub async fn ping_with(addr: Ipv6Addr, n: usize) -> io::Result<Ping> {
    let mut sock = RawV6Socket::new(PROTO_ICMPV6)?;
    sock.bind(Ipv6Addr::UNSPECIFIED)?;
    sock.connect(addr)?;

    let my_identifier = sock.as_raw_fd() as u16;
    let mut results = Vec::new();

    'outer: for i in 0..n {
        let echo = IcmpV6Echo {
            identifier: my_identifier,
            sequence_no: i as u16,
            data: random_bytes(52),
        };
        sock.send(&IcmpV6Packet::EchoRequest(echo.clone()).write_to_bytes()?)
            .await?;
        let send_time = SimTime::now();

        let deadline = SimTime::now() + Duration::from_secs(1);

        loop {
            let pkt = tokio::select! {
                res = sock.recv() => res,
                _ = sleep_until(deadline) => {
                    results.push(None);
                    continue 'outer;
                },
            };

            let pkt = pkt?;
            let icmp = IcmpV6Packet::peek_from(pkt.content)?;

            if let IcmpV6Packet::EchoReply(reply) = icmp {
                let is_valid = reply == echo;
                if !is_valid {
                    continue;
                }

                let rtt = send_time.elapsed();
                results.push(Some(rtt));
                break;
            }
        }
    }

    let mut time_min = Duration::MAX;
    let mut time_max = Duration::ZERO;
    let mut acc = Duration::ZERO;
    let mut n = 0u32;

    for &value in &results {
        if let Some(rtt) = value {
            if rtt < time_min {
                time_min = rtt;
            }
            if rtt > time_max {
                time_max = rtt
            }
            acc += rtt;
            n += 1;
        }
    }

    let time_avg = acc / n;
    let loss = (results.len() as f64 - n as f64) / results.len() as f64;

    Ok(Ping {
        addr,
        loss,
        time_min,
        time_max,
        time_avg,
    })
}

fn random_bytes(n: usize) -> Bytes {
    std::iter::repeat_with(des::runtime::random::<u8>)
        .take(n)
        .collect()
}

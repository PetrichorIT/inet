use std::{
    fmt,
    io::{self, Error, ErrorKind},
    net::Ipv4Addr,
    time::Duration,
};

use bytes_io::{Bytes, FromBytes, ToBytes};
use des::time::{SimTime, sleep_until};
use types::{
    icmpv4::{IcmpV4Packet, IcmpV4Type, PROTO_ICMPV4},
    ip::{Ipv4Flags, Ipv4Packet},
};

use crate::{ipv4::socket::RawV4Socket, socket::AsRawFd};

#[derive(Debug, Clone, PartialEq)]
pub struct Ping {
    pub addr: Ipv4Addr,
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

pub async fn ping(addr: Ipv4Addr) -> io::Result<Ping> {
    ping_with(addr, 3).await
}

pub async fn ping_with(addr: Ipv4Addr, n: usize) -> io::Result<Ping> {
    let mut sock = RawV4Socket::new(PROTO_ICMPV4)?;
    sock.bind(Ipv4Addr::UNSPECIFIED)?;
    sock.connect(addr)?;

    let mut results = Vec::new();
    let my_identifier = sock.as_raw_fd() as u16;

    'outer: for i in 0..n {
        let echo = IcmpV4Type::EchoRequest {
            identifier: my_identifier,
            sequence: i as u16,
        };
        let echo_pkt = IcmpV4Packet::new(
            echo,
            &Ipv4Packet {
                enc: 0,
                dscp: 0,
                identification: 0,
                flags: Ipv4Flags {
                    df: true,
                    mf: false,
                },
                fragment_offset: 0,
                ttl: 32,
                proto: PROTO_ICMPV4,
                src: Ipv4Addr::UNSPECIFIED,
                dst: addr,
                content: random_bytes(36),
            },
        );

        sock.send(&echo_pkt.write_to_bytes()?).await?;
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
            let icmp = IcmpV4Packet::peek_from(pkt.content)?;
            if let IcmpV4Type::EchoReply {
                identifier,
                sequence,
            } = icmp.typ
            {
                let is_valid = identifier == my_identifier && sequence == i as u16;
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

    if n == 0 {
        return Err(Error::new(ErrorKind::ConnectionRefused, "host unreachable"));
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

use std::{io, net::Ipv6Addr, time::Duration};

use bytes_io::{Bytes, FromBytes, ToBytes};
use des::runtime::random;
use des::time::{SimTime, sleep_until};
use types::icmpv6::{IcmpV6Packet, IcmpV6TimeExceededCode, PROTO_ICMPV6};
use types::udp::UdpPacket;

use crate::UdpSocket;
use crate::ipv6::socket::RawV6Socket;

/// The result of a call to `traceroute`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Traceroute {
    /// The target of the traced route.
    pub target: Ipv6Addr,
    /// A set of nodes identified allong the route to the
    /// target
    pub nodes: Vec<Trace>,
}

/// A node on a route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Trace {
    /// A node that responded to ICMP Echo Request,
    /// allowing for the computation of a RTT.
    Found {
        addr: Ipv6Addr,
        rtt: (Duration, Duration, Duration),
    },
    /// A non-responding node on the route.
    NotFound,
}

const TRACEROUTE_MAX: u8 = 32;

pub async fn traceroute(target: Ipv6Addr) -> io::Result<Traceroute> {
    let udp_socket = UdpSocket::bind("[::]:0").await?;
    let mut icmp_socket = RawV6Socket::new(PROTO_ICMPV6)?;
    icmp_socket.bind(Ipv6Addr::UNSPECIFIED)?;

    let local_addr = udp_socket.local_addr()?;

    let mut port = random::<u16>();
    let mut last_rtt = Duration::from_millis(200);
    let mut traceroute = Traceroute {
        target,
        nodes: Vec::new(),
    };

    'distance: for distance in 1..TRACEROUTE_MAX {
        udp_socket.set_ttl(distance)?;
        let mut results = Vec::new();

        const N: u16 = 3;

        'repeater: for i in 0..N {
            let cur_port = port.wrapping_add(i);
            udp_socket.connect((target, cur_port)).await?;
            icmp_socket.connect(target)?;

            let pkt = UdpPacket::new(local_addr.port(), port, Bytes::from_static(&[0; 12]));
            tracing::info!("send distance={distance} round={i} to {target}");
            udp_socket.writable().await?;
            let _ = udp_socket.take_error()?;
            udp_socket.send(&pkt.write_to_bytes()?).await?;
            let send_time = SimTime::now();

            // recv in a llop since we might recv a lot if icmp
            let deadline = SimTime::now() + last_rtt * 4;

            loop {
                let res = tokio::select! {
                    res = icmp_socket.recv() => res,
                    _ = sleep_until(deadline) => {
                        results.push(None);
                        continue 'repeater;
                    }
                };

                let pkt = res?;
                let icmp = IcmpV6Packet::peek_from(pkt.content)?;
                match icmp {
                    IcmpV6Packet::DestinationUnreachable(_) => break 'distance,
                    IcmpV6Packet::TimeExceeded(err) => match err.code {
                        IcmpV6TimeExceededCode::HopLimitExceeded => {
                            let rtt = send_time.elapsed();
                            tracing::info!("probe with rtt {rtt:?}");
                            results.push(Some((pkt.src, rtt)));
                            break;
                        }
                        _ => todo!(),
                    },
                    _ => continue,
                }
            }
        }

        port += N;

        let successes = results.iter().flatten().copied().collect::<Vec<_>>();
        if successes.is_empty() {
            traceroute.nodes.push(Trace::NotFound);
        } else {
            let reporter = successes[0].0;
            if !successes.iter().skip(1).all(|(addr, _)| *addr == reporter) {
                // Asymetric path -> make no assumpttions
                traceroute.nodes.push(Trace::NotFound);
                continue;
            }

            let min = *successes.iter().map(|(_, r)| r).min().unwrap();
            let max = *successes.iter().map(|(_, r)| r).max().unwrap();
            let sum = successes.iter().map(|(_, r)| *r).sum::<Duration>();
            let avg = sum / successes.len() as u32;

            last_rtt = last_rtt.max(avg);
            traceroute.nodes.push(Trace::Found {
                addr: reporter,
                rtt: (min, avg, max),
            });
        }
    }

    Ok(traceroute)
}

use bytes_io::FromBytes;
use des::{
    runtime::random,
    time::{SimTime, sleep},
};
use std::{
    io::{self, ErrorKind},
    net::Ipv6Addr,
    time::Duration,
};
use types::{ip::Ipv6Packet, udp::UdpPacket};

use crate::{
    IOHandle, UdpSocket,
    ctx::IOContext,
    ioctx,
    socket::{AsRawFd, Fd},
};

#[derive(Debug)]
#[allow(dead_code)]
pub struct TracerouteCB {
    fd: Fd,
    target: Ipv6Addr,
    segments: Vec<Segment>,
}

#[derive(Debug)]
struct Segment {
    target_port: u16,
    send_time: SimTime,
    bounceback: Option<(Ipv6Addr, SimTime)>,
}

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

pub async fn traceroute(addr: Ipv6Addr) -> io::Result<Traceroute> {
    ioctx().ipv6_traceroute(addr).await
}

impl IOHandle {
    pub async fn ipv6_traceroute(&self, addr: Ipv6Addr) -> io::Result<Traceroute> {
        let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;
        self.do_failable(|ctx| Ok(ctx.ipv6_icmp_register_traceroute(socket.as_raw_fd(), addr)))?;

        let mut port = random::<u16>();
        let mut distance = 1;
        let mut last_rtt = Duration::from_millis(200);
        let mut traceroute = Traceroute {
            target: addr,
            nodes: Vec::new(),
        };

        let mut failures = 0;

        loop {
            socket.set_ttl(distance)?;

            let mut last_err = None;

            // (1) Each distance 3 packets
            for _round in 0..3 {
                socket.connect((addr, port)).await?;
                last_err = last_err.or(socket.take_error()?); // < This is a dirty trick i do not like
                socket
                    .send(&[0; 12])
                    .await
                    .inspect_err(|e| tracing::error!("1:{e}"))?;

                self.do_failable(|ctx| Ok(ctx.ipv6_icmp_traceroute_register_segment(addr, port)))?;
                sleep(last_rtt / 4).await;

                port += 1;
            }

            // (2) Then wait for the response
            sleep(last_rtt * 4).await;

            // (3) Get segments back
            let segments =
                self.do_failable(|ctx| Ok(ctx.ipv6_icmp_traceroute_take_segments(addr)))?;

            let successes = segments
                .into_iter()
                .filter_map(|seg| {
                    let (reporter, recv_time) = seg.bounceback?;
                    Some((reporter, recv_time - seg.send_time))
                })
                .collect::<Vec<_>>();

            if successes.is_empty() {
                // (4a) Either no ICMP resonse at all or another error code
                match socket.take_error()? {
                    // Some other ICMP error was observed -> report it
                    Some(err) => {
                        if err.kind() == ErrorKind::ConnectionRefused
                            && err.to_string() == "destination unreachable"
                        {
                            return Ok(traceroute);
                        } else {
                            return Err(err);
                        }
                    }
                    // No ICMP error -> someone is not responding
                    None => {
                        failures += 1;
                        if failures == 3 {
                            traceroute.nodes.push(Trace::NotFound);
                            failures = 0;
                            distance += 1;
                        }
                    }
                }
            } else {
                let _ = socket.take_error()?;

                let reporter = successes[0].0;
                if !successes.iter().skip(1).all(|(addr, _)| *addr == reporter) {
                    // Asymetric path -> make no assumpttions
                    traceroute.nodes.push(Trace::NotFound);
                    distance += 1;
                    continue;
                }

                let min = *successes.iter().map(|(_, rtt)| rtt).min().unwrap();
                let max = *successes.iter().map(|(_, rtt)| rtt).max().unwrap();
                let sum = *successes.iter().map(|(_, rtt)| rtt).max().unwrap();
                let avg = sum / successes.len() as u32;

                last_rtt = avg;
                traceroute.nodes.push(Trace::Found {
                    addr: reporter,
                    rtt: (min, avg, max),
                });
                distance += 1;
            }
        }
    }
}

impl IOContext {
    fn ipv6_icmp_register_traceroute(&mut self, fd: Fd, addr: Ipv6Addr) {
        self.ipv6.traceroute_ctrl.insert(
            addr,
            TracerouteCB {
                fd,
                target: addr,
                segments: Vec::new(),
            },
        );
    }

    fn ipv6_icmp_traceroute_register_segment(&mut self, target: Ipv6Addr, target_port: u16) {
        let Some(trace) = self.ipv6.traceroute_ctrl.get_mut(&target) else {
            todo!()
        };
        trace.segments.push(Segment {
            target_port,
            send_time: SimTime::now(),
            bounceback: None,
        });
    }

    fn ipv6_icmp_traceroute_take_segments(&mut self, target: Ipv6Addr) -> Vec<Segment> {
        let Some(trace) = self.ipv6.traceroute_ctrl.get_mut(&target) else {
            todo!()
        };
        trace.segments.drain(..).collect()
    }

    pub(super) fn ipv6_icmp_traceroute_register_time_exceeded(
        &mut self,
        reporter: Ipv6Addr,
        original: &Ipv6Packet,
    ) {
        if let Some(trace) = self.ipv6.traceroute_ctrl.get_mut(&original.dst) {
            let Ok(udp_payload) = UdpPacket::peek_from(&original.content[..]) else {
                return;
            };
            if udp_payload.content[..] != [0; 12] {
                return;
            }

            if let Some(seg) = trace
                .segments
                .iter_mut()
                .find(|seg| seg.target_port == udp_payload.dst_port)
            {
                seg.bounceback = Some((reporter, SimTime::now()));
            }
        }
    }
}

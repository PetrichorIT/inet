use des::{
    runtime::random,
    time::{sleep, SimTime},
};
use std::{io, net::Ipv6Addr, time::Duration};

use crate::{
    ctx::IOContext,
    socket::{AsRawFd, Fd},
    UdpSocket,
};

#[allow(dead_code)]
pub struct TracerouteCB {
    pub fd: Fd,
    pub target: Ipv6Addr,
    pub last_send: SimTime,
    pub recent_err: Option<(Ipv6Addr, Duration)>,
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
    Found { addr: Ipv6Addr, rtt: Duration },
    /// A non-responding node on the route.
    NotFound,
}

pub async fn traceroute(addr: Ipv6Addr) -> io::Result<Traceroute> {
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;
    IOContext::failable_api(|ctx| Ok(ctx.ipv6_icmp_register_traceroute(socket.as_raw_fd(), addr)))?;

    let mut port = random::<u16>();
    let mut distance = 1;
    let mut last_rtt = Duration::from_millis(200);
    let mut traceroute = Traceroute {
        target: addr,
        nodes: Vec::new(),
    };

    'outer: loop {
        socket.set_ttl(distance)?;
        socket.connect((addr, port)).await?;
        socket.send(&[0; 8]).await?;

        IOContext::failable_api(|ctx| Ok(ctx.ipv6_icmp_register_sendtime_traceroute(addr)))?;
        sleep(last_rtt * 2).await;

        // let last_err = None;
        for _ in 0..4 {
            if let Some(e) = socket.take_error()? {
                if e.kind() == io::ErrorKind::ConnectionRefused {
                    // reached end port;
                    match &format!("{e}")[..] {
                        "PortUnreachable" => return Ok(traceroute),
                        _ => return Err(e),
                    }
                }

                if let Some(trace) =
                    IOContext::failable_api(|ctx| Ok(ctx.ipv6_icmp_get_error_traceroute(addr)))?
                {
                    traceroute.nodes.push(Trace::Found {
                        addr: trace.0,
                        rtt: trace.1,
                    });
                    last_rtt = trace.1;

                    port = port.wrapping_add(1);
                    distance += 1;
                    continue 'outer;
                } else {
                    // OTHER ERR
                    todo!()
                }
            } else {
                // TTL TO SHORT
                sleep(last_rtt * 2).await;
                continue;
            }
        }

        return Err(socket
            .take_error()?
            .unwrap_or(io::Error::new(io::ErrorKind::Other, "traceroute failed")));
        // return Err()
    }
}

impl IOContext {
    fn ipv6_icmp_register_traceroute(&mut self, fd: Fd, addr: Ipv6Addr) {
        self.ipv6.traceroute_ctrl.insert(
            addr,
            TracerouteCB {
                fd: fd,
                target: addr,
                last_send: SimTime::MIN,
                recent_err: None,
            },
        );
    }

    fn ipv6_icmp_register_sendtime_traceroute(&mut self, addr: Ipv6Addr) {
        let Some(trace) = self.ipv6.traceroute_ctrl.get_mut(&addr) else {
            todo!()
        };
        trace.last_send = SimTime::now();
    }

    fn ipv6_icmp_get_error_traceroute(&mut self, addr: Ipv6Addr) -> Option<(Ipv6Addr, Duration)> {
        let Some(trace) = self.ipv6.traceroute_ctrl.get_mut(&addr) else {
            todo!()
        };
        trace.recent_err.take()
    }
}

use crate::{
    socket::{AsRawFd, Fd},
    IOContext, UdpSocket,
};
use des::{
    runtime::random,
    time::{sleep, SimTime},
};
use std::{
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
    time::Duration,
};

#[allow(dead_code)]
pub(crate) struct TracerouteCB {
    pub fd: Fd,
    pub target: Ipv4Addr,
    pub last_send: SimTime,
    pub recent_err: Option<(Ipv4Addr, Duration)>,
}

/// The result of a call to `traceroute`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Traceroute {
    /// The target of the traced route.
    pub target: Ipv4Addr,
    /// A set of nodes identified allong the route to the
    /// target
    pub nodes: Vec<Trace>,
}

/// A node on a route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Trace {
    /// A node that responded to ICMP Echo Request,
    /// allowing for the computation of a RTT.
    Found { addr: Ipv4Addr, rtt: Duration },
    /// A non-responding node on the route.
    NotFound,
}

/// Traces all nodes allong a route to the target.
///
/// This functions tries to determine all memebers of the routing
/// path to the provided target. Nodes must respond to
/// ICMP Echo Requests to be identified.
pub async fn traceroute(addr: Ipv4Addr) -> Result<Traceroute> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    IOContext::failable_api(|ctx| Ok(ctx.traceroute_create(socket.as_raw_fd(), addr)))?;

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

        IOContext::failable_api(|ctx| Ok(ctx.traceroute_register_send(addr)))?;
        sleep(last_rtt * 2).await;

        // let last_err = None;
        for _ in 0..4 {
            if let Some(e) = socket.take_error()? {
                if e.kind() == ErrorKind::ConnectionRefused {
                    // reached end port;
                    match &format!("{e}")[..] {
                        "PortUnreachable" => return Ok(traceroute),
                        _ => return Err(e),
                    }
                }

                if let Some(trace) =
                    IOContext::failable_api(|ctx| Ok(ctx.traceroute_get_error(addr)))?
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
            .unwrap_or(Error::new(ErrorKind::Other, "traceroute failed")));
        // return Err()
    }
}

impl IOContext {
    fn traceroute_create(&mut self, fd: Fd, target: Ipv4Addr) {
        self.icmp.traceroutes.insert(
            target,
            TracerouteCB {
                fd,
                target,
                last_send: SimTime::MIN,
                recent_err: None,
            },
        );
    }

    fn traceroute_register_send(&mut self, target: Ipv4Addr) {
        let Some(trace) = self.icmp.traceroutes.get_mut(&target) else {
            return
        };
        trace.last_send = SimTime::now();
    }

    fn traceroute_get_error(&mut self, target: Ipv4Addr) -> Option<(Ipv4Addr, Duration)> {
        let Some(trace) = self.icmp.traceroutes.get_mut(&target) else {
            return None;
        };
        trace.recent_err.take()
    }
}

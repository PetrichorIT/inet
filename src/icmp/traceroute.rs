use crate::{
    socket::{AsRawFd, Fd},
    IOContext, UdpSocket,
};
use des::{
    runtime::random,
    time::{sleep, SimTime},
};
use std::{
    io::{Error, ErrorKind},
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Traceroute {
    pub nodes: Vec<Trace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Trace {
    Found { addr: Ipv4Addr, rtt: Duration },
    NotFound,
}

pub async fn traceroute(addr: Ipv4Addr) -> std::io::Result<Traceroute> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    IOContext::with_current(|ctx| ctx.traceroute_create(socket.as_raw_fd(), addr));

    let mut port = random::<u16>();
    let mut distance = 1;
    let mut last_rtt = Duration::from_millis(200);
    let mut traceroute = Traceroute { nodes: Vec::new() };

    'outer: loop {
        socket.set_ttl(distance)?;
        socket.connect((addr, port)).await?;
        socket.send(&[0; 8]).await?;

        IOContext::with_current(|ctx| ctx.traceroute_register_send(addr));
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

                if let Some(trace) = IOContext::with_current(|ctx| ctx.traceroute_get_error(addr)) {
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

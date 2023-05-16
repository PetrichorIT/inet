use des::runtime::random;

use crate::IOContext;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpConfig {
    pub rst_on_syn: bool,
    pub nack: bool,

    pub rx_buffer_size: u32,
    pub tx_buffer_size: u32,

    pub mss: u16,

    pub ttl: u32,
    pub timeout: Duration,
    pub timewait: Duration,
    pub listener_backlog: u32,
    pub syn_sent_thresh: usize,
    pub cong_ctrl: bool,

    pub linger: Option<Duration>,
    pub nodelay: bool,

    pub reuseport: bool,
    pub reuseaddr: bool,

    pub debug: bool,
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub(crate) struct TcpSocketConfig {
    pub addr: SocketAddr,
    pub linger: Option<Duration>,

    pub listen_backlog: u32,
    pub rx_buffer_size: u32,
    pub tx_buffer_size: u32,
    pub reuseaddr: bool,
    pub reuseport: bool,

    pub cong_ctrl: bool,
    pub connect_timeout: Duration,
    pub nodelay: bool,

    pub ttl: u32,
    pub inital_seq_no: u32,
    pub mss: u16,

    pub debug: bool,
}

impl TcpConfig {
    pub(crate) fn socket_v4(&self) -> TcpSocketConfig {
        TcpSocketConfig {
            addr: "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            linger: self.linger,

            listen_backlog: self.listener_backlog,
            rx_buffer_size: self.rx_buffer_size,
            tx_buffer_size: self.tx_buffer_size,
            reuseaddr: self.reuseaddr,
            reuseport: self.reuseport,

            connect_timeout: Duration::from_secs(2),
            nodelay: self.nodelay,

            ttl: self.ttl,
            inital_seq_no: random(),
            mss: self.mss,

            cong_ctrl: self.cong_ctrl,
            debug: self.debug,
        }
    }

    pub(crate) fn socket_v6(&self) -> TcpSocketConfig {
        TcpSocketConfig {
            addr: "[::0]:0".parse::<SocketAddr>().unwrap(),
            linger: self.linger,

            listen_backlog: self.listener_backlog,
            rx_buffer_size: self.rx_buffer_size,
            tx_buffer_size: self.tx_buffer_size,
            reuseaddr: self.reuseaddr,
            reuseport: self.reuseport,

            connect_timeout: Duration::from_secs(2),
            nodelay: self.nodelay,

            ttl: self.ttl,
            inital_seq_no: random(),
            mss: self.mss,

            cong_ctrl: self.cong_ctrl,
            debug: self.debug,
        }
    }

    pub(crate) fn listener(&self, addr: SocketAddr) -> TcpSocketConfig {
        TcpSocketConfig {
            addr,
            linger: self.linger,

            listen_backlog: self.listener_backlog,
            rx_buffer_size: self.rx_buffer_size,
            tx_buffer_size: self.tx_buffer_size,
            reuseaddr: self.reuseaddr,
            reuseport: self.reuseport,

            connect_timeout: Duration::from_secs(2),
            nodelay: self.nodelay,

            ttl: self.ttl,
            inital_seq_no: random(),
            mss: self.mss,

            cong_ctrl: self.cong_ctrl,
            debug: self.debug,
        }
    }

    pub(crate) fn stream(&self, addr: SocketAddr) -> TcpSocketConfig {
        TcpSocketConfig {
            addr,
            linger: None,

            listen_backlog: 1,
            rx_buffer_size: 2048,
            tx_buffer_size: 2048,
            reuseaddr: false,
            reuseport: false,

            connect_timeout: Duration::from_secs(2),
            nodelay: true,

            ttl: 64,
            inital_seq_no: random(),
            mss: 1024,

            cong_ctrl: self.cong_ctrl,
            debug: self.debug,
        }
    }
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            rst_on_syn: true,
            nack: false,

            rx_buffer_size: 0b1 << 15,
            tx_buffer_size: 0b1 << 15,
            listener_backlog: 32,

            mss: 1024,

            ttl: 20,
            timeout: Duration::from_secs(1),
            timewait: Duration::from_secs(1),
            syn_sent_thresh: 3,
            cong_ctrl: false,

            linger: None,
            nodelay: true,
            reuseaddr: true,
            reuseport: true,

            debug: false,
        }
    }
}

pub fn set_tcp_cfg(cfg: TcpConfig) -> Result<()> {
    IOContext::try_with_current(|ctx| {
        ctx.tcp.config = cfg;
    })
    .ok_or(Error::new(ErrorKind::Other, "missing IO plugin"))
}

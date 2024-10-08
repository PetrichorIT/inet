use fxhash::FxHashMap;
use std::net::SocketAddr;
use types::tcp::TcpPacket;

mod connection;
pub use connection::{Config, Connection, State};

use crate::socket::Fd;

#[cfg(test)]
mod tests;

pub struct Tcp {
    pub config: Config,
    pub handles: FxHashMap<Fd, TcpHandle>,
    pub binds: FxHashMap<Fd, ()>,
    pub streams: FxHashMap<Fd, Connection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHandle {
    pub quad: Quad,
    pub tx_buffer: Vec<TcpPacket>,
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl Tcp {
    pub fn new() -> Self {
        Tcp {
            config: Config::default(),
            handles: FxHashMap::default(),
            binds: FxHashMap::default(),
            streams: FxHashMap::default(),
        }
    }

    pub fn connect(&mut self, addr: SocketAddr, cfg: Option<Config>, fd: Option<Fd>) {}
}

impl Quad {
    pub fn is_ipv4(&self) -> bool {
        self.src.is_ipv4() && self.dst.is_ipv4()
    }

    fn default_mss(&self) -> u16 {
        if self.is_ipv4() {
            536
        } else {
            1220
        }
    }
}

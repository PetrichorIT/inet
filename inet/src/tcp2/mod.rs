use std::net::SocketAddr;

use inet_types::tcp::TcpPacket;

mod connection;
pub use connection::{Config, Connection, State};

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl Quad {
    pub fn is_ipv4(&self) -> bool {
        self.src.is_ipv4() && self.dst.is_ipv4()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHandle {
    pub quad: Quad,
    pub tx_buffer: Vec<TcpPacket>,
}

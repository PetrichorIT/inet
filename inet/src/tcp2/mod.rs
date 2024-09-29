use std::net::SocketAddr;

use inet_types::tcp::TcpPacket;

mod connection;
pub use connection::{Config, Connection, State};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct Quad {
    pub src: SocketAddr,
    pub dst: SocketAddr,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHandle {
    pub quad: Quad,
    pub tx_buffer: Vec<TcpPacket>,
}

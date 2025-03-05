use std::net::SocketAddr;

mod iterative;
mod pkt;
mod recursive;
mod root;
mod transaction;

pub use iterative::IterativeNameserver;
pub use pkt::*;
pub use recursive::RecursiveNameserver;
pub use root::*;
pub use transaction::*;

pub trait Nameserver: Send + 'static {
    fn tick(&mut self);
    fn incoming(&mut self, medium: TransportMedium, source: SocketAddr, msg: DnsMessage);

    fn ns_queries(&mut self) -> Vec<NameserverQuery>;
    fn active_queries(&self) -> Vec<NameserverQuery>;
    fn anwsers(&mut self) -> Vec<FinishedTransaction>;
}

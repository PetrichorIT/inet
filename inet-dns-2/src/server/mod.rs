use std::net::SocketAddr;

mod iterative;
mod pkt;
mod recursive;
mod root;
mod transaction;
mod types;

pub use iterative::IterativeNameserver;
pub use pkt::*;
pub use recursive::RecursiveNameserver;
pub use root::*;
pub use transaction::{ActiveTransaction, FinishedTransaction, TransactionResult};
pub use types::NameserverQuery;

pub trait Nameserver: 'static {
    fn tick(&mut self);
    fn incoming(&mut self, source: SocketAddr, msg: DnsMessage);
    fn queries(&mut self) -> impl Iterator<Item = NameserverQuery>;
    fn active_queries(&mut self) -> impl Iterator<Item = NameserverQuery>;

    fn anwsers(&mut self) -> impl Iterator<Item = FinishedTransaction>;
}

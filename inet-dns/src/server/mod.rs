//! Nameserver implementations

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

/// A trait representing a DNS nameserver.
///
/// Nameserver implementation details are open to implementing types. This trait can be used
/// to use custom nameservers together with common communication adapters.
pub trait Nameserver: Send + 'static {
    /// A method to perform periodic tasks.
    fn tick(&mut self);

    /// A method to handle incoming DNS messages.
    ///
    /// This method is called when a DNS message is received on a specific transport medium
    /// from a given source address. It should process the message and update the nameserver's
    /// state accordingly. Responses or subsequent queries should be generated, but not independently
    /// send without polling from the communication adapter.
    fn incoming(&mut self, medium: TransportMedium, source: SocketAddr, msg: DnsMessage);

    /// A method that returns the currently anwsered questions.
    ///
    /// Once called, the communication adapter is responsible for sending the responses.
    fn anwsers(&mut self) -> Vec<FinishedTransaction>;

    /// A method that returns the required nameserver queries.
    ///
    /// Once called, the communication adapter is responsible for sending the responses.
    fn ns_queries(&mut self) -> Vec<NameserverQuery>;

    /// A method indicating the currently active nameserver queries.
    fn active_queries(&self) -> Vec<NameserverQuery>;
}

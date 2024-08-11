use des::runtime::random;

use std::cell::RefCell;
use std::net::IpAddr;

use super::DnsIterativeNameserver;

thread_local! {
    pub(super) static ROOT_NS: RefCell<Vec<(IpAddr, String)>> = const { RefCell::new(Vec::new())}
}

impl DnsIterativeNameserver {
    pub fn all_root_ns(&self) -> Vec<(IpAddr, String)> {
        ROOT_NS.with(|root_ns| root_ns.borrow().clone())
    }

    pub fn one_root_ns(&self) -> (IpAddr, String) {
        ROOT_NS.with(|root_ns| {
            let root_ns = root_ns.borrow();
            root_ns[random::<usize>() % root_ns.len()].clone()
        })
    }
}

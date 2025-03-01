use des::runtime::random;

use std::cell::RefCell;
use std::net::IpAddr;

thread_local! {
    pub(super) static ROOT_NS: RefCell<Vec<(IpAddr, String)>> = const { RefCell::new(Vec::new())}
}

pub fn declare_root(addr: IpAddr, name: String) {
    tracing::trace!("declaring DNS root {addr}");
    ROOT_NS.with(|root_ns| {
        root_ns.borrow_mut().push((addr, name));
    });
}

pub fn all_root_ns() -> Vec<(IpAddr, String)> {
    ROOT_NS.with(|root_ns| root_ns.borrow().clone())
}

pub fn one_root_ns() -> (IpAddr, String) {
    ROOT_NS.with(|root_ns| {
        let root_ns = root_ns.borrow();
        root_ns[random::<usize>() % root_ns.len()].clone()
    })
}

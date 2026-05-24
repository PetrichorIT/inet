use std::cell::RefCell;
use std::net::IpAddr;

thread_local! {
    pub(super) static ROOT_NS: RefCell<Vec<(IpAddr, String)>> = const { RefCell::new(Vec::new())}
}

/// Returns all root nameservers.
#[must_use]
pub fn all_root_ns() -> Vec<(IpAddr, String)> {
    ROOT_NS.with(|root_ns| root_ns.borrow().clone())
}

/// Clears all root nameservers.
pub fn clear_root_ns() {
    ROOT_NS.with(|root_ns| {
        root_ns.borrow_mut().clear();
    });
}

/// Declares a root nameserver.
pub fn declare_root(addr: IpAddr, name: String) {
    tracing::trace!("declaring DNS root {addr}");
    ROOT_NS.with(|root_ns| {
        root_ns.borrow_mut().push((addr, name));
    });
}

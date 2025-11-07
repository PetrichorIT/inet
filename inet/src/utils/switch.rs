use crate::{env::RoutingInformation, interface::NetworkDevice, ioctx};
use des::prelude::*;
use types::iface::MacAddress;

/// An module that acts as a no-config link layer switch.
///
/// This switch learns MAC addresses, by observing incoming packages.
/// By virtue of using ARP, all ajacent nodes will identifiy themselves using either
/// ARP responses or ARP requests (broadcast) before any data is send, so
/// the switch will have learned all nessecary data.
#[derive(Debug, Default)]
pub struct LinkLayerSwitch {/* no content except io context */}

impl LinkLayerSwitch {
    pub const ADDR: MacAddress = MacAddress::new([1, 2, 3, 4, 5, 6]);
}

impl Module for LinkLayerSwitch {
    fn at_sim_start(&mut self, _stage: usize) {
        // collect all known ports and add them to the bridge
        let info = RoutingInformation::collect();
        let handle = ioctx();

        // create a interface bridge at a well known MAC addr
        let bridge = handle
            .add_bridge_interface("bridge0", Some(Self::ADDR))
            .expect("could not initialize bridge");

        // add all interfaces
        for (i, port) in info.ports.into_iter().enumerate() {
            handle
                .bridge_add_port(bridge, &format!("en{i}"), NetworkDevice::from(port))
                .expect("failed to add interface");
        }
    }
}

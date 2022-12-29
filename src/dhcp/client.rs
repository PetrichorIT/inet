use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
};

use des::{
    prelude::*,
    tokio::net::{get_mac_address, IOContext},
};

use super::common::{DHCPMessage, DHCPOpsTyp};
use crate::dhcp::{common::DHCPParameter, MESSAGE_KIND_DHCP};

pub struct DHCPClient {
    mac: [u8; 8],
    addr: Ipv4Addr,
    subnet: Ipv4Addr,
    dns: Ipv4Addr,
    // domain: String,
    router: Ipv4Addr,
    xid: u32,
    server_choosen: Ipv4Addr,

    gate: Option<GateRef>,

    start: SimTime,
    done: bool,
}

impl DHCPClient {
    pub fn new() -> Self {
        Self {
            mac: [0; 8],
            addr: Ipv4Addr::UNSPECIFIED,
            subnet: Ipv4Addr::UNSPECIFIED,
            dns: Ipv4Addr::UNSPECIFIED,
            // domain: String::new(),
            router: Ipv4Addr::UNSPECIFIED,
            xid: 0,
            server_choosen: Ipv4Addr::UNSPECIFIED,

            gate: gate("out", 0),

            start: SimTime::MAX,
            done: false,
        }
    }

    pub fn output_gate(&mut self, gate: GateRef) {
        self.gate = Some(gate)
    }

    pub fn start(&mut self, req_addr: Option<Ipv4Addr>) {
        let mac = get_mac_address()
            .expect("Failed to fetch MAC address for DHCP")
            .expect("No MAC address found for DHCP");
        self.mac = [0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];
        self.start = SimTime::now();
        self.done = false;

        let discover = DHCPMessage::discover(req_addr);
        self.xid = discover.xid;
        let udp_message = (
            SocketAddr::from_str("0.0.0.0:68").unwrap(),
            SocketAddr::from_str("255.255.255.255:67").unwrap(),
            discover,
        );

        log::trace!("<DHCPClient> Starting handshake {:x}", self.xid);
        send(
            Message::new()
                .kind(MESSAGE_KIND_DHCP)
                .content(udp_message)
                .build(),
            self.gate.as_ref().expect("Failed to provide valid gate"),
        )
    }

    pub fn handle_message(&mut self, udp: (SocketAddr, SocketAddr), msg: DHCPMessage) {
        match msg.ops.typ {
            DHCPOpsTyp::Offer => {
                if !self.addr.is_unspecified() {
                    return;
                }
                if msg.xid != self.xid {
                    return;
                }

                // respond instantly.
                assert_eq!(udp.0.ip(), IpAddr::V4(msg.siaddr));
                assert_eq!(udp.1.ip(), IpAddr::V4(msg.yiaddr));

                self.addr = msg.yiaddr;
                for op in &msg.ops.pars {
                    match op {
                        DHCPParameter::SubnetMask(mask) => self.subnet = *mask,
                        DHCPParameter::Router(router) => self.router = *router,
                        DHCPParameter::DomainNameServer(dns) => self.dns = *dns,
                        DHCPParameter::DomainName() => {
                            // self.domain = String::from_utf8_lossy(&msg.sname).into_owned()
                        }
                        _ => {}
                    }
                }

                let req = DHCPMessage::request(msg);

                self.server_choosen = req.siaddr;
                log::trace!(
                    "<DHCPClient> Accepted offer {:x} of {:?} for addr {:?}",
                    req.xid,
                    req.siaddr,
                    req.ciaddr
                );

                let udp = (
                    SocketAddr::new(IpAddr::V4(self.addr), 68),
                    SocketAddr::new(IpAddr::V4(req.siaddr), 67),
                    req,
                );
                send(
                    Message::new().kind(MESSAGE_KIND_DHCP).content(udp).build(),
                    self.gate.as_ref().expect("Failed to provide valid gate"),
                );
            }
            DHCPOpsTyp::Ack => {
                if msg.xid != self.xid || msg.siaddr != self.server_choosen {
                    return;
                }

                if self.done {
                    return;
                }

                assert_eq!(msg.yiaddr, self.addr);

                log::info!(
                    "DHCP config complete: now known as {:?} from {:?}",
                    self.addr,
                    msg.siaddr
                );
                // Commit values to tokio
                let mac = get_mac_address().unwrap();
                let mac = mac.unwrap_or(random());
                IOContext::new(mac, self.addr).set();
                self.done = true;
                send(Message::new().kind(1000).content(self.addr).build(), "out")
            }
            _ => {}
        }
    }
}

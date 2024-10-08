use std::{
    hash::Hash,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::{Deref, DerefMut},
    str::FromStr,
};

use des::prelude::*;
use fxhash::{FxBuildHasher, FxHashMap};
use types::iface::MacAddress;

use crate::{dhcp::MESSAGE_KIND_DHCP, utils::get_ip};

use super::common::{DHCPMessage, DHCPOp, DHCPOpsTyp, DHCPParameter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DHCPServer {
    transactions: FxHashMap<u32, (SimTime, TransactionState)>,
    addr: Ipv4Addr,

    // pars
    gate: Option<GateRef>,

    // state
    reserved: FxHashMap<Ipv4Addr, MacAddress>,

    // config
    config: DHCPServerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NodeConfig {
    pub addr: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub router: Ipv4Addr,
    pub subnet: Ipv4Addr,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TransactionState {
    offered: NodeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DHCPServerConfig {
    static_ow: FxHashMap<MacAddress, Ipv4Addr>,

    subnet_mask: Ipv4Addr,
    subnet_range_start: Ipv4Addr,
    subnet_range_end: Ipv4Addr,

    dns: Ipv4Addr,
    router: Ipv4Addr,

    timeout: Duration,
    lease_time: Duration,
}

impl DHCPServerConfig {
    pub fn add_static_entry(&mut self, mac: MacAddress, addr: Ipv4Addr) -> &mut Self {
        self.static_ow.insert(mac, addr);
        self
    }

    pub fn remove_static_entry(&mut self, mac: MacAddress) -> &mut Self {
        self.static_ow.remove(&mac);
        self
    }

    pub fn subnet_range(&mut self, start: Ipv4Addr, end: Ipv4Addr) -> &mut Self {
        self.subnet_range_start = start;
        self.subnet_range_end = end;
        self
    }

    pub fn subnet_mask(&mut self, mask: Ipv4Addr) -> &mut Self {
        self.subnet_mask = mask;
        self
    }

    pub fn dns(&mut self, dns: Ipv4Addr) -> &mut Self {
        self.dns = dns;
        self
    }

    pub fn router(&mut self, router: Ipv4Addr) -> &mut Self {
        self.router = router;
        self
    }

    pub fn timeouts(&mut self, timeout: Duration, lease_time: Duration) -> &mut Self {
        self.timeout = timeout;
        self.lease_time = lease_time;
        self
    }
}

impl Default for DHCPServerConfig {
    fn default() -> Self {
        Self {
            static_ow: FxHashMap::with_hasher(FxBuildHasher::default()),

            subnet_mask: Ipv4Addr::UNSPECIFIED,
            subnet_range_start: Ipv4Addr::UNSPECIFIED,
            subnet_range_end: Ipv4Addr::UNSPECIFIED,
            dns: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,

            timeout: Duration::new(10, 0),
            lease_time: Duration::new(100_000, 0),
        }
    }
}

impl DHCPServer {
    pub fn new() -> Self {
        let addr = if let IpAddr::V4(v4) = get_ip().unwrap() {
            v4
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        let mut reserved = FxHashMap::with_hasher(FxBuildHasher::default());
        reserved.insert(addr, MacAddress::NULL);
        DHCPServer {
            transactions: FxHashMap::with_hasher(FxBuildHasher::default()),
            addr,
            reserved,
            gate: gate("out", 0),
            config: DHCPServerConfig::default(),
        }
    }

    pub fn handle_message(&mut self, udp: (SocketAddr, SocketAddr), msg: DHCPMessage) {
        if msg.op == DHCPOp::Wakeup {
            for key in self.transactions.keys().copied().collect::<Vec<_>>() {
                let (timestamp, _) = self.transactions.get(&key).unwrap();
                if SimTime::now().duration_since(*timestamp) >= self.config.timeout {
                    let (_, transaction) = self.transactions.remove(&key).unwrap();
                    tracing::trace!("<DHCPServer> Canceled handshake {:x} due to timeout", key);
                    // remove reserved entry
                    self.reserved.remove(&transaction.offered.addr).unwrap();
                }
            }

            return;
        }

        match msg.ops.typ {
            DHCPOpsTyp::Discover => {
                assert_eq!(udp.0, SocketAddr::from_str("0.0.0.0:68").unwrap());
                assert_eq!(udp.1, SocketAddr::from_str("255.255.255.255:67").unwrap());

                let config = self.config_for_discover(&msg);
                let ops = self.ops_from_config_for_offer(&msg, &config);
                let offer = DHCPMessage::offer(msg, self.addr, config.addr, ops);

                tracing::trace!(
                    "<DHCPServer> Initiated handshake {:x} with offer {:?}",
                    offer.xid,
                    offer.yiaddr
                );

                schedule_in(
                    Message::new()
                        .kind(MESSAGE_KIND_DHCP)
                        .content((
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                            DHCPMessage::wakeup(),
                        ))
                        .build(),
                    self.config.timeout,
                );

                let udp = (
                    SocketAddr::new(IpAddr::V4(self.addr), 67),
                    SocketAddr::new(IpAddr::V4(offer.yiaddr), 68),
                    offer,
                );
                send(
                    Message::new().kind(MESSAGE_KIND_DHCP).content(udp).build(),
                    self.gate.as_ref().expect("Failed to fetch gate"),
                );
            }
            DHCPOpsTyp::Request => {
                let config = self.transactions.remove_entry(&msg.xid);
                let Some((_, (_timestamp, config))) = config else {
                    return;
                };

                if msg.siaddr != self.addr {
                    tracing::trace!(
                        "<DHCPServer> Canceled handshake {:x}. Handled by other instance {:?}",
                        msg.xid,
                        msg.siaddr
                    );
                    self.reserved.remove(&config.offered.addr);
                    return;
                }

                assert_eq!(config.offered.addr, msg.ciaddr);
                assert_eq!(config.offered.addr, msg.ciaddr);
                let ops = self.ops_from_config_for_offer(&msg, &config.offered);
                let ack = DHCPMessage::ack(msg, ops);

                tracing::trace!(
                    "<DHCPServer> Finished handshake {:x} with binding {:?}",
                    ack.xid,
                    ack.yiaddr
                );

                let udp = (
                    SocketAddr::new(IpAddr::V4(self.addr), 67),
                    SocketAddr::new(IpAddr::V4(ack.ciaddr), 68),
                    ack,
                );

                send(
                    Message::new().kind(MESSAGE_KIND_DHCP).content(udp).build(),
                    self.gate.as_ref().expect("Failed to fetch gate"),
                );
            }
            _ => {}
        }
    }

    fn config_for_discover(&mut self, discover: &DHCPMessage) -> NodeConfig {
        let req_ip = discover
            .ops
            .pars
            .iter()
            .filter_map(|v| {
                if let DHCPParameter::AddressRequested(addr) = v {
                    Some(*addr)
                } else {
                    None
                }
            })
            .next();

        // static overwrote
        if let Some(overwrite) = self.config.static_ow.get(&discover.chaddr) {
            NodeConfig {
                addr: *overwrite,
                dns: self.config.dns,
                router: self.config.router,
                subnet: self.config.subnet_mask,
                name: String::new(),
            }
        } else {
            if let Some(req_ip) = req_ip {
                let possible = self.reserved.get(&req_ip).is_none();
                let possible = possible && self.dynamic_ip_in_range(req_ip);
                if possible {
                    let config = NodeConfig {
                        addr: req_ip,
                        dns: self.config.dns,
                        router: self.config.router,
                        subnet: self.config.subnet_mask,
                        name: String::new(),
                    };

                    self.reserved.insert(req_ip, discover.chaddr);
                    self.transactions.insert(
                        discover.xid,
                        (
                            SimTime::now(),
                            TransactionState {
                                offered: config.clone(),
                            },
                        ),
                    );
                    return config;
                }
            }

            // get ip in range
            let mut ip = u32::from_be_bytes(self.config.subnet_range_start.octets());
            let bound = u32::from_be_bytes(self.config.subnet_range_end.octets());

            let res = loop {
                if ip >= bound {
                    break None;
                }
                let bytes = ip.to_be_bytes();
                let addr = Ipv4Addr::from(bytes);
                if self.reserved.get(&addr).is_none() {
                    break Some(addr);
                }
                ip += 1;
            };
            if let Some(res) = res {
                let config = NodeConfig {
                    addr: res,
                    dns: self.config.dns,
                    router: self.config.router,
                    subnet: self.config.subnet_mask,
                    name: String::new(),
                };

                self.reserved.insert(res, discover.chaddr);
                self.transactions.insert(
                    discover.xid,
                    (
                        SimTime::now(),
                        TransactionState {
                            offered: config.clone(),
                        },
                    ),
                );
                config
            } else {
                unimplemented!()
            }
        }
    }

    fn ops_from_config_for_offer(
        &self,
        discover: &DHCPMessage,
        config: &NodeConfig,
    ) -> Vec<DHCPParameter> {
        let mut res = Vec::new();
        if discover
            .ops
            .pars
            .iter()
            .any(|v| matches!(v, DHCPParameter::ReqDomainName))
        {
            res.push(DHCPParameter::DomainName()); // TODO
        }

        if discover
            .ops
            .pars
            .iter()
            .any(|v| matches!(v, DHCPParameter::ReqDomainNameServer))
        {
            res.push(DHCPParameter::DomainNameServer(config.dns));
        }

        if discover
            .ops
            .pars
            .iter()
            .any(|v| matches!(v, DHCPParameter::ReqRouter))
        {
            res.push(DHCPParameter::Router(config.router));
        }

        if discover
            .ops
            .pars
            .iter()
            .any(|v| matches!(v, DHCPParameter::ReqSubnetMask))
        {
            res.push(DHCPParameter::SubnetMask(config.subnet));
        }
        res
    }

    fn dynamic_ip_in_range(&self, ip: Ipv4Addr) -> bool {
        let lower = u32::from_be_bytes(self.config.subnet_range_start.octets());
        let upper = u32::from_be_bytes(self.config.subnet_range_end.octets());
        let ip = u32::from_be_bytes(ip.octets());
        lower <= ip && ip < upper
    }
}

impl Deref for DHCPServer {
    type Target = DHCPServerConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl DerefMut for DHCPServer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            dns: Ipv4Addr::UNSPECIFIED,
            subnet: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            name: String::new(),
        }
    }
}

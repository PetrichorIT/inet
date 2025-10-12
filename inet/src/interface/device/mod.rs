use std::any::Any;

use crate::{
    env::{RoutingInformation, RoutingPort},
    interface::device::driver::{EthernetDeviceDriver, LoopbackDeviceDriver},
};
use des::{
    net::module::current,
    prelude::{GateRef, Header, Message},
    time::SimTime,
};

use super::{InterfaceBusyState, MacAddress};

mod driver;

pub use driver::MediumDeviceDriver;

/// A descriptor for a network device that handles the
/// sending and receiving of MTUs.
#[derive(Debug)]
pub struct NetworkDevice {
    /// The physical address of the associated device
    pub addr: MacAddress,
    pub mtu: Option<usize>,
    inner: Box<dyn MediumDeviceDriver>,
}

pub enum NetworkDeviceReadiness {
    Ready,
    Busy(SimTime),
}

impl From<NetworkDeviceReadiness> for InterfaceBusyState {
    fn from(value: NetworkDeviceReadiness) -> Self {
        match value {
            NetworkDeviceReadiness::Ready => InterfaceBusyState::Idle,
            NetworkDeviceReadiness::Busy(until) => InterfaceBusyState::Busy {
                until,
                interests: Vec::new(),
            },
        }
    }
}

fn as_any(v: &dyn MediumDeviceDriver) -> &dyn Any {
    v
}

impl NetworkDevice {
    #[inline]
    pub fn from_raw<T: MediumDeviceDriver>(addr: MacAddress, inner: T) -> Self {
        Self {
            addr,
            mtu: None,
            inner: Box::new(inner),
        }
    }

    pub fn is_loopback(&self) -> bool {
        as_any(&*self.inner).is::<LoopbackDeviceDriver>()
    }

    pub fn input(&self) -> Option<GateRef> {
        Some(
            as_any(&*self.inner)
                .downcast_ref::<EthernetDeviceDriver>()?
                .receiving
                .clone(),
        )
    }

    /// Creates a local, loopback device.
    pub fn loopback() -> Self {
        Self::from_raw(MacAddress::NULL, LoopbackDeviceDriver {})
    }

    pub fn gate(name: &str, pos: usize) -> Option<Self> {
        let gate = current().gate((name, pos))?;
        Some(Self::from_gate(gate))
    }

    pub fn from_gate(gate: GateRef) -> Self {
        Self::from_raw(
            MacAddress::generate(),
            EthernetDeviceDriver::new(gate.clone(), gate),
        )
    }

    /// Creates the default ethernet device using the gates
    /// "in" and "out" as a duplex connection point.
    pub fn eth() -> Self {
        let mut rinfo = RoutingInformation::collect();
        match rinfo.ports.len() {
            0 => panic!("cannot create default ethernet device, module has no duplex port"),
            1 => {
                let port = rinfo.ports.swap_remove(0);
                Self {
                    addr: MacAddress::generate(),
                    mtu: None,
                    inner: Box::new(EthernetDeviceDriver::new(port.output, port.input)),
                }
            }
            _ => {
                let default_port = rinfo
                    .ports
                    .into_iter()
                    .find(|p| p.input.name() == "port" && p.input.pos() == 0);

                if let Some(default_port) = default_port {
                    Self::from_raw(
                        MacAddress::generate(),
                        EthernetDeviceDriver::new(default_port.output, default_port.input),
                    )
                } else {
                    panic!(
                        "cannot create default ethernet device, module has mutiple valid ports, but not (in/out)"
                    )
                }
            }
        }
    }

    /// Creates a new device, by using the first routing port that
    /// statifies `f`.
    pub fn eth_select(f: impl Fn(&RoutingPort) -> bool) -> Self {
        let rinfo = RoutingInformation::collect();
        for r in rinfo.ports {
            let valid = f(&r);
            if valid {
                return Self::from_raw(
                    MacAddress::generate(),
                    EthernetDeviceDriver::new(r.output, r.input),
                );
            }
        }

        unimplemented!("{:?}", RoutingInformation::collect())
    }

    pub fn bidirectional(name: impl AsRef<str>) -> Self {
        let name = name.as_ref();
        let rinfo = RoutingInformation::collect();
        for r in rinfo.ports {
            if r.name == name {
                return Self {
                    addr: MacAddress::generate(),
                    mtu: None,
                    inner: Box::new(EthernetDeviceDriver::new(r.output, r.input)),
                };
            }
        }

        unimplemented!("{:?}", RoutingInformation::collect())
    }

    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = Some(mtu);
        self
    }

    pub(crate) fn mtu(&self) -> usize {
        let t_mtu = self.inner.mtu();
        self.mtu.map_or(t_mtu, |limit| limit.min(t_mtu))
    }

    pub(super) fn ready(&self) -> NetworkDeviceReadiness {
        self.inner.ready()
    }

    pub(super) fn send(&mut self, mut msg: Message) -> NetworkDeviceReadiness {
        msg.header.src = self.addr.into();
        self.inner.send(msg)
    }

    pub(super) fn matches(&self, last_gate: &Header) -> bool {
        self.inner.matches(last_gate)
    }
}

impl From<RoutingPort> for NetworkDevice {
    fn from(port: RoutingPort) -> Self {
        NetworkDevice {
            addr: MacAddress::generate(),
            mtu: None,
            inner: Box::new(EthernetDeviceDriver::new(port.output, port.input)),
        }
    }
}

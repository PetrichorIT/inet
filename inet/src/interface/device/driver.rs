use std::{any::Any, fmt::Debug, time::Duration};

use des::prelude::{ChannelRef, GateRef, Message, schedule_in, send};

use crate::interface::NetworkDeviceReadiness;

pub trait MediumDeviceDriver: Any + Debug {
    fn mtu(&self) -> usize;
    fn ready(&self) -> NetworkDeviceReadiness;
    fn send(&mut self, msg: Message) -> NetworkDeviceReadiness;
    fn matches(&self, header: &Message) -> bool;
}

#[derive(Debug)]
pub struct EthernetDeviceDriver {
    pub(super) receiving: GateRef,
    sending: GateRef,
    channel: Option<ChannelRef>,
}

impl EthernetDeviceDriver {
    pub fn new(receiving: GateRef, sending: GateRef) -> Self {
        let channel = sending.next_channel();
        Self {
            receiving,
            sending,
            channel,
        }
    }
}

const ETHERNET_MTU: usize = 1500;

impl MediumDeviceDriver for EthernetDeviceDriver {
    fn mtu(&self) -> usize {
        ETHERNET_MTU
    }

    fn ready(&self) -> NetworkDeviceReadiness {
        let Some(chan) = &self.channel else {
            return NetworkDeviceReadiness::Ready;
        };

        if chan.is_busy() {
            NetworkDeviceReadiness::Busy(chan.transmission_finish_time().unwrap())
        } else {
            NetworkDeviceReadiness::Ready
        }
    }

    fn send(&mut self, msg: Message) -> NetworkDeviceReadiness {
        if let Some(channel) = &self.channel {
            assert!(!channel.is_busy(), "busy connector");
            // NOTE: the 1ns delay could be removed, since channels now ignore
            // event order for unbusying events aka send() operations that somehow occur before the
            // unbusy notif at the same time t, acknowledge that the channel is not busy,

            send(msg, &self.sending).expect("failed due to unknown channel issue");
            let tft = channel.transmission_finish_time().unwrap();

            NetworkDeviceReadiness::Busy(tft)
        } else {
            send(msg, &self.sending).expect("no channel, cannot fail"); // TODO: how to handle dead peers
            NetworkDeviceReadiness::Ready
        }
    }

    fn matches(&self, header: &Message) -> bool {
        Some(&self.receiving) == header.last_gate.as_ref()
    }
}

#[derive(Debug)]
pub struct LoopbackDeviceDriver {}

#[derive(Debug)]
pub struct LoopbackFrame;

const LOOPBACK_MTU: usize = 16384;

impl MediumDeviceDriver for LoopbackDeviceDriver {
    fn mtu(&self) -> usize {
        LOOPBACK_MTU
    }

    fn ready(&self) -> NetworkDeviceReadiness {
        NetworkDeviceReadiness::Ready
    }

    fn send(&mut self, msg: Message) -> NetworkDeviceReadiness {
        schedule_in(msg.with_extension(LoopbackFrame), Duration::ZERO);
        NetworkDeviceReadiness::Ready
    }

    fn matches(&self, header: &Message) -> bool {
        header.last_gate.is_none() && header.extensions.has::<LoopbackFrame>()
    }
}

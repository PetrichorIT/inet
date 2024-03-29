use crate::types::AsNumber;
use inet::TcpStream;
use std::{fmt::Debug, future::Future, io::Result, pin::Pin};

use super::stream::BgpStream;

#[derive(Debug)]
pub(crate) enum PeeringKind {
    Internal,
    External,
}

impl PeeringKind {
    pub fn for_as(host: AsNumber, peer: AsNumber) -> Self {
        if host == peer {
            Self::Internal
        } else {
            Self::External
        }
    }
}

pub(super) enum NeighborDeamonState {
    Idle,
    Connect(Pin<Box<dyn Future<Output = Result<TcpStream>> + Send>>),
    Active,
    ActiveDelayOpen(BgpStream),
    OpenSent(BgpStream),
    OpenConfirm(BgpStream),
    Established(BgpStream),
}

impl Debug for NeighborDeamonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Connect(_) => write!(f, "Connect"),
            Self::Active => write!(f, "Active"),
            Self::ActiveDelayOpen(stream) => {
                write!(f, "ActiveDelayOpen({})", stream.peer_addr().unwrap())
            }
            Self::OpenSent(stream) => write!(f, "OpenSent({})", stream.peer_addr().unwrap()),
            Self::OpenConfirm(stream) => write!(f, "OpenConfirm({})", stream.peer_addr().unwrap()),
            Self::Established(stream) => write!(f, "Established({})", stream.peer_addr().unwrap()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BgpPeeringCfg {
    pub colliosion_detect: bool,
    pub damp_peer_oscillation: bool,
    pub delay_open: bool,
    pub passiv_tcp_estab: bool,
    pub notif_without_open: bool,
}

impl Default for BgpPeeringCfg {
    fn default() -> Self {
        Self {
            colliosion_detect: false,
            damp_peer_oscillation: false,
            delay_open: false,
            passiv_tcp_estab: false,
            notif_without_open: false,
        }
    }
}

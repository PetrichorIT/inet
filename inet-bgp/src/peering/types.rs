use crate::types::AsNumber;
use inet::TcpStream;
use std::{fmt::Debug, future::Future, io::Result, pin::Pin};

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

pub(crate) enum NeighborDeamonState {
    Idle,
    Connect(Pin<Box<dyn Future<Output = Result<TcpStream>> + Send>>),
    Active,
    ActiveDelayOpen(TcpStream),
    OpenSent(TcpStream),
    OpenConfirm(TcpStream),
    Established(TcpStream),
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
pub(crate) struct BgpPeeringCfg {
    pub(crate) colliosion_detect: bool,
    pub(crate) damp_peer_oscillation: bool,
    pub(crate) delay_open: bool,
    pub(crate) passiv_tcp_estab: bool,
    pub(crate) notif_without_open: bool,
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

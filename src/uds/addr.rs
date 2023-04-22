use std::{
    fmt::Debug,
    path::{Path, PathBuf},
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SocketAddr {
    pub(super) sockaddr: SocketAddrInner,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SocketAddrInner {
    Unnamed,
    Path(PathBuf),
    Abstract(Vec<u8>),
}

impl SocketAddr {
    pub fn is_unamed(&self) -> bool {
        matches!(self.sockaddr, SocketAddrInner::Unnamed)
    }

    pub fn as_pathname(&self) -> Option<&Path> {
        match self.sockaddr {
            SocketAddrInner::Path(ref path) => Some(path),
            _ => None,
        }
    }
}

impl Debug for SocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.sockaddr {
            SocketAddrInner::Unnamed => write!(f, "(unamed)"),
            SocketAddrInner::Path(ref path) => write!(f, "{:?}", path),
            SocketAddrInner::Abstract(ref buf) => write!(f, "{}", String::from_utf8_lossy(buf)),
        }
    }
}

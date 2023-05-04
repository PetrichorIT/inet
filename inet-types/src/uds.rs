use std::{
    fmt::Debug,
    path::{Path, PathBuf},
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SocketAddr {
    sockaddr: SocketAddrInner,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SocketAddrInner {
    Unnamed,
    Path(PathBuf),
    // Abstract(Vec<u8>),
}

impl SocketAddr {
    pub fn unnamed() -> Self {
        Self {
            sockaddr: SocketAddrInner::Unnamed,
        }
    }

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
            SocketAddrInner::Path(ref path) => write!(f, "{:?} (pathname)", path),
            // SocketAddrInner::Abstract(ref buf) => write!(f, "{}", String::from_utf8_lossy(buf)),
        }
    }
}

impl From<PathBuf> for SocketAddr {
    fn from(value: PathBuf) -> Self {
        SocketAddr {
            sockaddr: SocketAddrInner::Path(value),
        }
    }
}

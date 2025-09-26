#![warn(clippy::pedantic)]
//! Unix Domain Sockets (UDS)

use fxhash::FxBuildHasher;
use fxhash::FxHashMap;
use inet::socket::Fd;

mod addr;
mod dgram;
mod dstream;

pub use self::dgram::*;
pub use self::dstream::*;
pub use addr::SocketAddr;

pub(crate) struct UdsExtension {
    dgrams: FxHashMap<Fd, UnixDatagramHandle>,
    listeners: FxHashMap<Fd, UnixListenerHandle>,
}

impl Default for UdsExtension {
    fn default() -> Self {
        Self {
            dgrams: FxHashMap::with_hasher(FxBuildHasher::default()),
            listeners: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

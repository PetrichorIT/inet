//! Unix Domain Sockets (UDS)

use crate::socket::Fd;
use fxhash::FxBuildHasher;
use fxhash::FxHashMap;

mod dgram;
mod stream;

pub use self::dgram::*;
pub use self::stream::*;

pub(crate) struct Uds {
    pub(super) dgrams: FxHashMap<Fd, UnixDatagramHandle>,
    pub(super) binds: FxHashMap<Fd, UnixListenerHandle>,
}

impl Uds {
    pub fn new() -> Self {
        Self {
            dgrams: FxHashMap::with_hasher(FxBuildHasher::default()),
            binds: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

//! Unix Domain Sockets (UDS)

use fxhash::FxBuildHasher;
use fxhash::FxHashMap;
use inet::extensions::load_ext;
use inet::socket::Fd;

mod dgram;
// mod stream;

pub use self::dgram::*;
// pub use self::stream::*;

pub(crate) struct UdsExtension {
    dgrams: FxHashMap<Fd, UnixDatagramHandle>,
    // binds: FxHashMap<Fd, UnixListenerHandle>,
}

impl UdsExtension {
    pub fn new() -> Self {
        Self {
            dgrams: FxHashMap::with_hasher(FxBuildHasher::default()),
            // binds: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

pub fn enable_uds() {
    load_ext(UdsExtension::new())
}

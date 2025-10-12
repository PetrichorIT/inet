use des::net::module::try_current;
use serde::{Deserialize, Serialize};
use valuable::Valuable;

use super::{Connection, State};

#[derive(Debug, Clone, PartialEq, Eq, Valuable, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub state: State,
    pub seq_no: u32,
    pub ack_no: u32,
}

impl Connection {
    pub fn info(&self) -> ConnectionInfo {
        ConnectionInfo {
            state: self.state,
            seq_no: self.snd.nxt,
            ack_no: self.rcv.nxt,
        }
    }

    #[inline]
    pub fn publish(&self) {
        if cfg!(feature = "props") && self.cfg.allow_publish {
            let Some(module) = try_current() else { return };
            module
                .prop::<ConnectionInfo>(&format!(
                    "inet.tcp2.stream@{}-{}",
                    self.quad.src, self.quad.dst
                ))
                .expect("typing failed")
                .set(self.info());
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if cfg!(feature = "props") && self.cfg.allow_publish {
            let Some(module) = try_current() else { return };
            module
                .prop_raw(&format!(
                    "inet.tcp2.stream@{}-{}",
                    self.quad.src, self.quad.dst
                ))
                .clear()
        }
    }
}

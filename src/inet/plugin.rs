use super::IOContext;
use des::{net::plugin::Plugin, prelude::Message};

/// A plugin managing IO primitives provided by inet.
pub struct IOPlugin {
    ctx: Option<IOContext>,
    prev: Option<IOContext>,
}

impl IOPlugin {
    /// Creates a new plugin without defined network devices.
    pub fn new() -> Self {
        Self {
            ctx: Some(IOContext::empty()),
            prev: None,
        }
    }
}

impl Plugin for IOPlugin {
    fn capture_sim_start(&mut self) {
        self.capture(None);
    }
    fn capture_sim_end(&mut self) {
        self.capture(None);
    }
    fn capture(&mut self, msg: Option<Message>) -> Option<Message> {
        let io = self.ctx.take().expect("Theft");
        self.prev = IOContext::swap_in(Some(io));

        if let Some(msg) = msg {
            IOContext::with_current(|ctx| ctx.capture(msg))
        } else {
            None
        }
    }

    fn defer_sim_start(&mut self) {
        self.defer();
    }
    fn defer_sim_end(&mut self) {
        self.defer()
    }
    fn defer(&mut self) {
        // Defer intent resolve

        self.ctx = IOContext::swap_in(self.prev.take());
        assert!(self.ctx.is_some());
    }
}

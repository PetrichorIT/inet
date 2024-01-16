use super::IOContext;
use des::{
    net::{module::current, processing::ProcessingElement},
    prelude::{Message, ModuleId},
};

/// A plugin managing IO primitives provided by inet.
pub struct IOPlugin {
    ctx: Option<Box<IOContext>>,
    prev: Option<Box<IOContext>>,
}

impl IOPlugin {
    /// Creates a new plugin without defined network devices.
    pub(super) fn new(id: ModuleId) -> Self {
        Self {
            ctx: Some(Box::new(IOContext::new(id))),
            prev: None,
        }
    }
}

impl ProcessingElement for IOPlugin {
    fn event_start(&mut self) {
        let io = self.ctx.take().expect("Theft");
        self.prev = IOContext::swap_in(Some(io));
    }

    fn incoming(&mut self, msg: Message) -> Option<Message> {
        IOContext::with_current(|ctx| ctx.recv(msg))
    }

    fn event_end(&mut self) {
        self.ctx = IOContext::swap_in(self.prev.take());
        let Some(ref mut ctx) = self.ctx else {
            panic!("Stole CTX")
        };

        if ctx.meta_changed {
            ctx.meta_changed = false;
            current().set_meta(ctx.meta());
        }
    }
}

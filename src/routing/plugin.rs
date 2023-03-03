use super::{Router, RoutingInformation};
use des::net::plugin::Plugin;
use std::panic::UnwindSafe;

pub struct RoutingPlugin<R: Router>(R, bool);

impl<R: Router> RoutingPlugin<R> {
    pub fn new(router: R) -> Self {
        Self(router, false)
    }
}

impl<R: Router + 'static> Plugin for RoutingPlugin<R> {
    fn event_start(&mut self) {
        if !self.1 {
            self.1 = true;
            self.0.initalize(RoutingInformation::collect());
        }
    }

    fn capture_incoming(&mut self, msg: des::prelude::Message) -> Option<des::prelude::Message> {
        match self.0.route(msg) {
            Ok(()) => None,
            Err(e) => Some(e),
        }
    }
}

impl<R: Router> UnwindSafe for RoutingPlugin<R> {}

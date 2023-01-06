use std::panic::UnwindSafe;

use des::prelude::Plugin;

use super::{Router, RoutingInformation};

pub struct RoutingPlugin<R: Router>(pub R);

impl<R: Router> Plugin for RoutingPlugin<R> {
    fn capture_sim_start(&mut self) {
        self.0.initalize(RoutingInformation::collect())
    }

    fn capture(&mut self, msg: Option<des::prelude::Message>) -> Option<des::prelude::Message> {
        if let Some(msg) = msg {
            match self.0.route(msg) {
                Ok(()) => None,
                Err(e) => Some(e),
            }
        } else {
            None
        }
    }

    fn defer(&mut self) {}
}

impl<R: Router> UnwindSafe for RoutingPlugin<R> {}

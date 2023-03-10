use super::Router;
use des::prelude::*;

pub struct StackedRoutingDeamon {
    routers: Vec<Box<dyn Router>>,
}

impl StackedRoutingDeamon {
    pub fn new(routers: Vec<Box<dyn Router>>) -> Self {
        Self { routers }
    }
}

impl Router for StackedRoutingDeamon {
    fn initalize(&mut self, routing_info: super::RoutingInformation) {
        for router in self.routers.iter_mut() {
            router.initalize(routing_info.clone())
        }
    }

    fn accepts(&mut self, msg: &Message) -> bool {
        for router in self.routers.iter_mut() {
            if router.accepts(msg) {
                return true;
            }
        }
        false
    }

    fn route(&mut self, mut msg: Message) -> Result<(), Message> {
        for router in self.routers.iter_mut() {
            if router.accepts(&msg) {
                match router.route(msg) {
                    Ok(()) => return Ok(()),
                    Err(v) => msg = v,
                }
            }
        }
        Err(msg)
    }
}

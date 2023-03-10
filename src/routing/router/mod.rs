mod random;
use des::prelude::Message;

pub use self::random::RandomRoutingDeamon;

mod backward;
pub use self::backward::BackwardRoutingDeamon;

mod stacked;
pub use self::stacked::StackedRoutingDeamon;

mod par_based;
pub use self::par_based::ParBasedRoutingDeamon;

mod plugin;
pub use self::plugin::RoutingPlugin;

use super::RoutingInformation;

pub trait Router {
    fn initalize(&mut self, routing_info: RoutingInformation);
    fn accepts(&mut self, msg: &Message) -> bool;
    fn route(&mut self, msg: Message) -> Result<(), Message>;
}

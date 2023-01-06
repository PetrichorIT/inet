use des::prelude::*;

mod edge;
mod networks;
mod routers;

use networks::*;
use routers::WANRouter;

#[NdlSubsystem("bin")]
struct Main {}

fn main() {
    inet::init();

    ScopedLogger::new()
        .interal_max_log_level(log::LevelFilter::Warn)
        .finish()
        .unwrap();

    let app: NetworkRuntime<SubsystemRef> = Main {}.build_rt();
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));

    let _result = rt.run().unwrap();
}

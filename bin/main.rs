use des::{prelude::*, registry};

mod edge;
mod networks;
mod routers;

use edge::*;
use networks::*;
use routers::*;

struct Main;
impl Module for Main {
    fn new() -> Main {
        Main
    }
}

fn main() {
    inet::init();
    Logger::new()
        .interal_max_log_level(log::LevelFilter::Warn)
        .set_logger();

    let mut app: NetworkRuntime<NdlApplication> = NetworkRuntime::new(
        NdlApplication::new(
            "bin/main.ndl",
            registry![TypeA, TypeB, TypeC, LANRouter, WANRouter, EdgeNode, Main],
        )
        .map_err(|e| println!("{e}"))
        .unwrap(),
    );
    app.include_par_file("bin/main.par");
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));

    let _result = rt.run().unwrap();
}

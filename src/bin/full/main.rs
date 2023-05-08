use des::{prelude::*, registry};
use inet::utils::LinkLayerSwitch;

struct Node;
impl Module for Node {
    fn new() -> Self {
        Self
    }
}
struct Dns;
impl Module for Dns {
    fn new() -> Self {
        Self
    }
}

struct Router;
impl Module for Router {
    fn new() -> Self {
        Self
    }
}
struct LAN;
impl Module for LAN {
    fn new() -> Self {
        Self
    }
}
struct Main;
impl Module for Main {
    fn new() -> Self {
        Self
    }
}

fn main() {
    inet::init();

    Logger::new().set_logger();

    type Switch = LinkLayerSwitch;

    let app = NdlApplication::new(
        "src/bin/full/main.ndl",
        registry![Dns, Node, Router, Switch, LAN, Main],
    )
    .map_err(|e| println!("{e}"))
    .unwrap();
    let mut app = NetworkApplication::new(app);
    app.include_par_file("src/bin/full/main.par");
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let _ = rt.run();
}

use des::{prelude::*, registry};

macro_rules! empty_module {
    ($t:tt) => {
        struct $t;

        impl Module for $t {
            fn new() -> Self {
                Self
            }
        }
    };
}

empty_module!(Client);
empty_module!(Server);
empty_module!(Switch);
empty_module!(Router);
empty_module!(Network);
empty_module!(Main);

fn main() {
    inet::init();

    let app = NetworkApplication::new(
        NdlApplication::new(
            "ideal_bin/main.ndl",
            registry![Client, Server, Switch, Router, Network, Main],
        )
        .map_err(|e| println!("{e}"))
        .unwrap(),
    );

    let rt = Runtime::new(app);
    let _ = rt.run();
}

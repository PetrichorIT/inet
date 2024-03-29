use std::time::Duration;

use des::{
    net::{AsyncFn, Sim},
    runtime::Builder,
    time::sleep,
};
use inet::extensions::{load_ext, with_ext};

#[test]
fn basic_extension() {
    inet::init();

    struct MyExt {
        value: usize,
    }

    let mut sim = Sim::new(());
    sim.node(
        "mynode",
        AsyncFn::new(|_| async move {
            load_ext(MyExt { value: 42 });
            sleep(Duration::from_secs(1)).await;

            with_ext::<MyExt, _>(|ext| {
                assert_eq!(ext.value, 42);
                println!("success")
            });
        }),
    );

    let rt = Builder::new().build(sim);
    let _ = rt.run().unwrap();
}

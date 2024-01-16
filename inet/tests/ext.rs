use std::time::Duration;

use des::{net::AsyncBuilder, runtime::Builder, time::sleep};
use inet::extensions::{load_ext, with_ext};

#[test]
fn basic_extension() {
    inet::init();

    struct MyExt {
        value: usize,
    }

    let mut sim = AsyncBuilder::new();
    sim.node("mynode", |_| async move {
        load_ext(MyExt { value: 42 });
        sleep(Duration::from_secs(1)).await;

        with_ext::<MyExt, _>(|ext| {
            assert_eq!(ext.value, 42);
            println!("success")
        });

        Ok(())
    });

    let rt = Builder::new().build(sim.build());
    let _ = rt.run().unwrap();
}

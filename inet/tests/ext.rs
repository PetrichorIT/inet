use std::time::Duration;

use des::{
    net::{Sim, handlers::AsyncHandler},
    runtime::{Builder, RuntimeError},
    time::sleep,
};
use inet::extensions::with_ext;

#[test]
fn basic_extension() -> Result<(), RuntimeError> {
    #[derive(Default)]
    struct MyExt {
        value: usize,
    }

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "mynode",
        AsyncHandler::new(|_| async move {
            with_ext(|e| *e = MyExt { value: 42 });
            sleep(Duration::from_secs(1)).await;

            with_ext::<MyExt, _>(|ext| {
                assert_eq!(ext.value, 42);
                println!("success")
            });
        }),
    );

    let rt = Builder::new().build(sim.freeze());
    rt.run().map(|_| ())
}

use std::time::Duration;

use des::{Sim, runtime::handlers::AsyncHandler, time::sleep};
use inet::{extensions::ExtensionHandle, ioctx};

#[test]
fn basic_extension() -> Result<(), des::Failure> {
    #[derive(Default)]
    struct MyExt {
        value: usize,
    }

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "mynode",
        AsyncHandler::new(|_| async move {
            let ext = ExtensionHandle::<MyExt>::new();
            assert_eq!(format!("{:?}", ioctx()), "IOHandle");
            assert_eq!(format!("{ext:?}"), "ExtensionHandle");

            ext.with(|e| *e = MyExt { value: 42 });
            sleep(Duration::from_secs(1)).await;

            ext.with(|ext| {
                assert_eq!(ext.value, 42);
                println!("success");
            });
        }),
    );

    let rt = sim.seeded(123).build();
    rt.run().into_result().map(|_| ())
}

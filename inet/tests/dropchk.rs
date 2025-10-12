use std::{future::pending, sync::atomic::AtomicBool};

use des::{
    net::{Sim, handlers::AsyncHandler},
    runtime::{Builder, RuntimeError},
};
use inet::ioctx;
use serial_test::serial;

#[test]
#[serial]
fn io_context_is_dropped() -> Result<(), RuntimeError> {
    static DONE: AtomicBool = AtomicBool::new(false);

    #[derive(Default)]
    struct MyExt {
        ival: i32,
    }
    impl Drop for MyExt {
        fn drop(&mut self) {
            DONE.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "alice",
        AsyncHandler::io(|_| async move {
            let hold_handle = ioctx().get_extension::<MyExt>();
            hold_handle.with(|e| e.ival = 32);
            pending::<()>().await;
            drop(hold_handle);
            Ok(())
        }),
    );
    drop(
        Builder::seeded(123)
            .max_time(10.0.into())
            .build(sim.freeze())
            .run()?,
    );

    assert!(DONE.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}

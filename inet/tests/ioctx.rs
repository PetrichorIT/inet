use std::{
    panic::{catch_unwind, set_hook, take_hook},
    sync::{Arc, atomic::AtomicBool},
};

use inet::ioctx;

#[test]
#[serial_test::serial]
fn panic_at_no_ioctx() {
    let result = Arc::new(AtomicBool::new(false));
    let r = result.clone();

    set_hook(Box::new(move |info| {
        let loc = info.location().expect("no loc found");
        r.store(loc.file() == file!(), std::sync::atomic::Ordering::SeqCst); // track_caller
    }));
    catch_unwind(|| {
        let _ = ioctx();
    })
    .expect_err("should have panicked");
    let _ = take_hook();

    assert!(result.load(std::sync::atomic::Ordering::SeqCst))
}

use std::any::Any;

use crate::ctx::IOContext;

pub fn load_ext<E: Any>(ext: E) {
    IOContext::with_current(|ctx| ctx.extensions.load_ext(ext))
}

pub fn with_ext<E: Any, R>(f: impl FnOnce(&mut E) -> R) -> Option<R> {
    IOContext::with_current(|ctx| ctx.extensions.with_ext(f))
}

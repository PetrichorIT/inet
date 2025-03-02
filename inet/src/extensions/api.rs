use std::any::Any;

use crate::ctx::IOContext;

pub fn load_ext<E: Default + Any>(value: E) {
    IOContext::with_current(|ctx| ctx.extensions.with_ext(|val| *val = value))
}

pub fn with_ext<E: Default + Any, R>(f: impl FnOnce(&mut E) -> R) -> R {
    IOContext::with_current(|ctx| ctx.extensions.with_ext(f))
}

pub fn try_with_ext<E: Default + Any, R>(f: impl FnOnce(&mut E) -> R) -> Option<R> {
    IOContext::try_with_current(|ctx| ctx.extensions.with_ext(f))
}

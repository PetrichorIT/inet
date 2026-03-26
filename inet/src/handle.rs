use std::{
    fmt::Debug,
    io::{Error, Result},
    sync::{Arc, LazyLock, Mutex, Weak},
};

use des::prelude::{current, try_current};

use crate::ctx::IOContext;

static CURRENT: LazyLock<Mutex<Option<IOHandle>>> = const { LazyLock::new(Mutex::default) };

/// Retrieves the current IO handle.
#[track_caller]
#[inline]
pub fn ioctx() -> IOHandle {
    IOHandle::current()
}

#[derive(Clone)]
#[repr(transparent)]
pub struct IOHandle(pub(super) Arc<Mutex<IOContext>>);

pub(super) type IOHandleWeak = Weak<Mutex<IOContext>>;

impl IOHandle {
    #[track_caller]
    pub fn current() -> Self {
        let lock = CURRENT.lock().expect("could not aquire io context lock");
        lock.as_ref()
            .cloned()
            .expect("could not aquire handle to IO context (no active context found)")
    }

    pub(super) fn swap_in(ingoing: Option<IOHandle>) -> Option<IOHandle> {
        let mut lock = CURRENT.lock().expect("could not aquire io context lock");
        let ret = lock.take();
        *lock = ingoing.inspect(|ctx| {
            ctx.0.lock().expect("failed to lock").path = current().path();
        });
        ret
    }

    #[track_caller]
    pub(super) fn try_do_io<R>(&self, f: impl FnOnce(&mut IOContext) -> R) -> Option<R> {
        Some(f(&mut *self.0.try_lock().ok()?))
    }

    #[track_caller]
    pub(super) fn do_readonly<T>(&self, f: impl FnOnce(&IOContext) -> T) -> T {
        let ctx = self.0.lock().expect("failed to get inner io context");
        f(&ctx)
    }

    #[track_caller]
    pub(super) fn do_mutating<R>(&self, f: impl FnOnce(&mut IOContext) -> R) -> R {
        let mut ctx = self.0.lock().expect("failed to get inner io context");
        f(&mut ctx)
    }

    #[track_caller]
    pub(super) fn do_mutating_on_active_module<T>(
        &self,
        f: impl FnOnce(&mut IOContext) -> Result<T>,
    ) -> Result<T> {
        let mut ctx = self.0.lock().expect("failed to get inner io context");
        // Require that the curretn exectuting context is valid
        let module = try_current().ok_or_else(|| Error::other("in drop chain"))?;
        if module.path() != ctx.path {
            return Err(Error::other("invalid executing context"));
        }

        f(&mut ctx)
    }
}

impl Debug for IOHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IOHandle").finish()
    }
}

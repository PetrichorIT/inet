use fxhash::{FxBuildHasher, FxHashMap};
use std::{
    any::{Any, TypeId},
    fmt::Debug,
    marker::PhantomData,
};

use crate::IOHandle;

impl IOHandle {
    pub fn get_extension<E: Default + Any>(&self) -> ExtensionHandle<E> {
        ExtensionHandle {
            handle: self.clone(),
            _phantom: PhantomData,
        }
    }
}

pub struct ExtensionHandle<E> {
    handle: IOHandle,
    _phantom: PhantomData<E>,
}

impl<E> Debug for ExtensionHandle<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionHandle").finish()
    }
}

impl<E> Clone for ExtensionHandle<E> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<E: Default + Any> ExtensionHandle<E> {
    pub fn new() -> Self {
        Self {
            handle: IOHandle::current(),
            _phantom: PhantomData,
        }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut E) -> R) -> R {
        self.handle.do_io(|ctx| ctx.extensions.with_ext(f))
    }

    pub fn try_with<R>(&self, f: impl FnOnce(&mut E) -> R) -> Option<R> {
        self.handle.try_do_io(|ctx| ctx.extensions.with_ext(f))
    }
}

#[derive(Default)]
pub struct Extensions {
    mapping: FxHashMap<TypeId, Box<dyn Any>>,
}

impl Extensions {
    pub fn new() -> Self {
        Self {
            mapping: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }

    pub fn with_ext<E: Default + Any, R>(&mut self, f: impl FnOnce(&mut E) -> R) -> R {
        let ext = self
            .mapping
            .entry(TypeId::of::<E>())
            .or_insert(Box::new(E::default()));
        f(ext.downcast_mut::<E>().expect("internal errror"))
    }
}

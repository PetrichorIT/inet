use fxhash::{FxBuildHasher, FxHashMap};
use std::any::{Any, TypeId};

use crate::IOContext;

pub fn load_ext<E: Default + Any>(value: E) {
    IOContext::with_current(|ctx| ctx.extensions.with_ext(|val| *val = value))
}

pub fn with_ext<E: Default + Any, R>(f: impl FnOnce(&mut E) -> R) -> R {
    IOContext::with_current(|ctx| ctx.extensions.with_ext(f))
}

pub fn try_with_ext<E: Default + Any, R>(f: impl FnOnce(&mut E) -> R) -> Option<R> {
    IOContext::try_with_current(|ctx| ctx.extensions.with_ext(f))
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

    fn with_ext<E: Default + Any, R>(&mut self, f: impl FnOnce(&mut E) -> R) -> R {
        let ext = self
            .mapping
            .entry(TypeId::of::<E>())
            .or_insert(Box::new(E::default()));
        f(ext.downcast_mut::<E>().expect("internal errror"))
    }
}

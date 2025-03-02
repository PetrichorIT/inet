use fxhash::{FxBuildHasher, FxHashMap};
use std::any::{Any, TypeId};

mod api;
pub use self::api::*;

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

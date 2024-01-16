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

    fn load_ext<E: Any>(&mut self, ext: E) {
        self.mapping.insert(TypeId::of::<E>(), Box::new(ext));
    }

    fn with_ext<E: Any, R>(&mut self, f: impl FnOnce(&mut E) -> R) -> Option<R> {
        if let Some(ext) = self.mapping.get_mut(&TypeId::of::<E>()) {
            Some(f(ext.downcast_mut::<E>().expect("internal errror")))
        } else {
            None
        }
    }
}

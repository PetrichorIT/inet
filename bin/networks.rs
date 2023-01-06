use des::prelude::*;

use super::edge::EdgeNode;
use super::routers::LANRouter;

#[NdlModule("bin")]
pub struct TypeA {}

impl Module for TypeA {
    fn new() -> Self {
        Self {}
    }
}

#[NdlModule("bin")]
pub struct TypeB {}

impl Module for TypeB {
    fn new() -> Self {
        Self {}
    }
}

#[NdlModule("bin")]
pub struct TypeC {}

impl Module for TypeC {
    fn new() -> Self {
        Self {}
    }
}

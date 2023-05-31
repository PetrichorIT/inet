#[allow(unused)]
macro_rules! impl_build_named {
    ($t:ty) => {
        #[allow(unused)]
        impl $t {
            fn build_named(
                path: ::des::net::ObjectPath,
                _rt: &mut ::des::net::NetworkApplication<()>,
            ) -> ModuleRef {
                let mref = ::des::net::module::ModuleContext::standalone(path);
                mref.activate();
                let this = Box::new(<$t as Module>::new());
                mref.upgrade_dummy(this);
                mref
            }

            fn build_named_with_parent(
                name: &str,
                parent: ModuleRef,
                _rt: &mut ::des::net::NetworkApplication<()>,
            ) -> ModuleRef {
                // (1) Create empty module contxt bound to path.
                let mref = ::des::net::module::ModuleContext::child_of(name, parent);

                // (4) Build and attach custom state
                mref.activate();
                let this = Box::new(<Self as Module>::new());
                mref.upgrade_dummy(this);

                mref
            }
        }
    };
}

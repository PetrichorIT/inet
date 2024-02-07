#[allow(unused)]
macro_rules! impl_build_named {
    ($t:ty) => {
        #[allow(unused)]
        impl $t {
            fn build_named(
                path: ::des::net::ObjectPath,
                _rt: &mut ::des::net::NetworkApplication<()>,
            ) -> ::des::net::module::ModuleRef {
                let mref = ::des::net::module::ModuleContext::standalone(path);
                mref.activate();
                use ::des::net::module::Module;
                use ::des::net::processing::IntoProcessingElements;
                let this = <$t as Module>::new().as_processing_chain();
                mref.upgrade_dummy(this);
                mref
            }

            fn build_named_with_parent(
                name: &str,
                parent: ::des::net::module::ModuleRef,
                _rt: &mut ::des::net::NetworkApplication<()>,
            ) -> ::des::net::module::ModuleRef {
                use ::des::net::module::Module;
                // (1) Create empty module contxt bound to path.
                let mref = ::des::net::module::ModuleContext::child_of(name, parent);

                // (4) Build and attach custom state
                mref.activate();
                let this = <Self as Module>::new().as_processing_chain();
                mref.upgrade_dummy(this);

                mref
            }
        }
    };
}

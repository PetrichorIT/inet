macro_rules! primitve_enum_repr {
    (
        $(#[$outer:meta])*
        $vis: vis enum $ident: ident {
            type Repr = $repr:ty;
            $(
                $variant:ident = $prim:literal,
            )+
        };
    ) => {
        $(#[$outer])*
        #[repr($repr)]
        $vis enum $ident {
            $(
                $variant = $prim,
            )+
        }

        impl $ident {
            #[allow(unused)]
            $vis fn to_raw(self) -> $repr {
                self as $repr
            }

            #[allow(unused)]
            $vis fn from_raw(raw: $repr) -> Option<Self> {
                match raw {
                    $(
                        $prim => Some(Self::$variant),
                    )+
                    _ => None
                }
            }
        }
    };
}

macro_rules! inet_trace {
    (target: $target:expr, $($arg:tt)+) => { compile_error!("No you dont") };
    ($($arg:tt)+) => { log::trace!(target: &format!("{}@inet", ::des::net::module::module_path()), $($arg)+) };
}

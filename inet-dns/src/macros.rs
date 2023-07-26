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
            #[must_use]
            $vis fn to_raw(self) -> $repr {
                self as $repr
            }

            #[allow(unused)]
            #[must_use]
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

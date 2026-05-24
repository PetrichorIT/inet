/// An macro to automatically implement `ToBytestream` and `FromBytestream`
/// for primitive enumerations with `#[repr(ux)]`
#[macro_export]
macro_rules! repr_enum {
    ($(#[$outer:meta])*
    $vis: vis enum $ident: ident {
        type Repr = $repr:ty where $order:ty;
        $(
            $(#[$inner:meta])*
            $variant:ident = $prim:literal,
        )+
        $(
            = default $default_variant:ident
        )?
    }) => {
        $(#[$outer])*
        #[repr($repr)]
        $vis enum $ident {
            $(
                $(#[$inner])*
                $variant = $prim,
            )+
            $(
                $default_variant($repr),
            )?
        }

        impl ::std::str::FromStr for $ident {
            type Err = ::std::io::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(
                        stringify!($variant) => Ok(Self::$variant),
                    )+
                    _ => Err(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidInput,
                        "unknown string: ".to_string() + s
                    ))
                }
            }
        }

        impl $ident {
            $vis fn from_raw_repr(repr: $repr) -> ::std::io::Result<Self> {
                match repr {
                    $(
                        $prim => Ok(Self::$variant),
                    )+
                    $(
                        _ => Ok(Self::$default_variant(repr)),
                    )?
                    _ => Err(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidInput,
                        "unknown discriminant"
                    ))
                }
            }

            $vis fn to_raw_repr(&self) -> $repr {
                match self {
                    $(
                        Self::$variant => $prim,
                    )+
                    $(
                        Self::$default_variant(repr) => *repr,
                    )?
                }
            }
        }
    };
}

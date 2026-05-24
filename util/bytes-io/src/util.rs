use std::fmt::Debug;

use crate::{FromBytes, ToBytes};

/// Asserts that encoding and decoding a value round-trips.
///
/// # Panics
///
/// if the test fails.
#[track_caller]
pub fn assert_encoding_e2e<T, E>(values: &[T])
where
    T: FromBytes<Error = E>,
    T: ToBytes<Error = E>,
    T: PartialEq + Debug,
    E: Debug,
{
    for value in values {
        let encoded = match value.write_to_vec() {
            Ok(encoded) => encoded,
            Err(err) => panic!("encoding of value failed: value = {value:?}, \nerror = {err:?}"),
        };
        let mut encoded_for_decoding = &encoded[..];

        let decoded = match T::read_from(&mut encoded_for_decoding) {
            Ok(decoded) => decoded,
            Err(err) => panic!(
                "decoding of value failed: value = {value:?}, \nbytes = {encoded:?}, \nerror = {err:?}"
            ),
        };

        assert_eq!(*value, decoded, "value must be equal after encode->decode");

        assert!(
            encoded_for_decoding.is_empty(),
            "decoding left some bytes behind: value = {value:?}, \nbytes = {encoded:?} \nremaining bytes = {encoded_for_decoding:?}"
        );

        let reencoded = decoded.write_to_bytes_mut().expect(
            "technically unreachable, since decpded == value and value was already encoded",
        );
        assert_eq!(
            encoded, reencoded,
            "there are some issues with PartialEq or non-deterministic encoding"
        );
    }
}

macro_rules! impl_for_primitive {
    ($($t:ty),*) => {
        $(
            impl crate::ToBytes for $t {
                type Error = ::std::io::Error;
                fn to_bytes(&self, w: &mut crate::BytesWriter<'_>) -> Result<(), Self::Error> {
                    use ::std::io::Write;
                    w.write_all(&self.to_be_bytes())
                }
            }

            impl crate::FromBytes for $t {
                type Error = ::std::io::Error;
                fn from_bytes(r: &mut crate::BytesReader<'_>) -> Result<Self, Self::Error> {
                    use ::std::io::Read;
                    let mut buf = [0; std::mem::size_of::<$t>()];
                    r.read_exact(&mut buf)?;
                    Ok(<$t>::from_be_bytes(buf))
                }
            }
        )*
    };
}

impl_for_primitive! { u8,u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize }

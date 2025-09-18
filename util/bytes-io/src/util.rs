use std::fmt::Debug;

use crate::{FromBytes, ToBytes};

/// Asserts that encoding and decoding a value round-trips.
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
            "decoding left some bytes behind: value = {value:?}, \nbytes = {encoded:?} \nremaining bytes = {:?}",
            encoded_for_decoding
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

// pub enum MaybeBytes {
//     Bytes(Bytes),
//     Unencoded(Box<dyn MaybeEncodable>),
// }

// pub trait MaybeEncodable:
//     Any + FromBytes<Error = std::io::Error> + ToBytes<Error = std::io::Error>
// {
//     fn byte_len(&self) -> usize;
// }

// pub enum Borrowed<'a, T> {
//     Owned(T),
//     Borrowed(&'a T),
// }

// impl<'a, T> Deref for Borrowed<'a, T> {
//     type Target = T;
//     fn deref(&self) -> &Self::Target {
//         match self {
//             Self::Owned(t) => t,
//             Self::Borrowed(t) => *t,
//         }
//     }
// }

// impl MaybeBytes {
//     pub fn as_bytes(&self) -> Bytes {
//         match self {
//             MaybeBytes::Bytes(bytes) => bytes.clone(),
//             MaybeBytes::Unencoded(encodable) => encodable
//                 .write_to_bytes()
//                 .expect("expected encoding not to fail"),
//         }
//     }

//     pub fn as_value<T: MaybeEncodable + ToOwned>(&self) -> Cow<'_, T> {
//         match self {
//             MaybeBytes::Bytes(bytes) => {
//                 let mut bytes_for_decoding = &bytes[..];
//                 Cow::Owned(
//                     T::read_from(&mut bytes_for_decoding).expect("expected decoding not to fail"),
//                 )
//             }
//             MaybeBytes::Unencoded(encodable) => {
//                 let as_any: &dyn Any = &*encodable;
//                 Cow::Borrowed(as_any.downcast_ref::<T>().expect("expected type to match"))
//             }
//         }
//     }
// }

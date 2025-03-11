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

        let reencoded = decoded.write_to_bytes().expect(
            "technically unreachable, since decpded == value and value was already encoded",
        );
        assert_eq!(
            encoded, reencoded,
            "there are some issues with PartialEq or non-deterministic encoding"
        );
    }
}

use super::*;
use ::byteorder::{ReadBytesExt, WriteBytesExt, BE};
use std::io::Error;

#[test]
fn a() {
    #[derive(Debug)]
    struct A {
        vals: Vec<u16>,
        trail: u64,
    }
    impl ToBytestream for A {
        type Error = Error;
        fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
            let marker = stream.create_typed_marker::<u16>()?;
            for val in &self.vals {
                stream.write_u16::<BE>(*val)?;
            }
            let len = stream.len_since_marker(&marker) as u16;
            stream.update_marker(&marker).write_u16::<BE>(len)?;
            stream.write_u64::<BE>(self.trail)?;
            Ok(())
        }
    }

    impl FromBytestream for A {
        type Error = Error;
        fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
            let len = stream.read_u16::<BE>()?;
            let mut substr = stream.extract(len as usize)?;
            let mut vals = Vec::new();
            while !substr.is_empty() {
                vals.push(substr.read_u16::<BE>()?);
            }
            let trail = stream.read_u64::<BE>()?;

            Ok(Self { vals, trail })
        }
    }

    let a = A {
        vals: vec![1, 2, 3, 4],
        trail: u64::MAX,
    };
    let mut buf = a.to_vec().unwrap();
    let new = A::read_from_vec(&mut buf);

    println!("{:?}", a);
    println!("{:?}", buf);
    println!("{:?}", new);
}

#[derive(Debug, PartialEq, Eq)]
struct AB {
    a: u32,
    b: u32,
}
impl FromBytestream for AB {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        Ok(Self {
            a: stream.read_u32::<BE>()?,
            b: stream.read_u32::<BE>()?,
        })
    }
}

#[test]
fn drain_from_vec() {
    let mut vec = vec![0, 0, 0, 0, 255, 255, 255, 255, 0, 1, 2, 3];
    let ab = AB::read_from_vec(&mut vec).unwrap();
    assert_eq!(ab, AB { a: 0, b: u32::MAX });
    assert_eq!(vec, [0, 1, 2, 3]);
}

#[test]
fn from_mut_slice() {
    let buf = [0, 0, 0, 0, 255, 255, 255, 255, 0, 1, 2, 3];
    let mut slice = &buf[..];
    let ab = AB::read_from_slice(&mut slice).unwrap();
    assert_eq!(ab, AB { a: 0, b: u32::MAX });
    assert_eq!(slice, [0, 1, 2, 3]);
}

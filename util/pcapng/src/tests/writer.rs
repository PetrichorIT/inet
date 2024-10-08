use crate::{tests::SAMPLE_RAW_IP_PACKETS, BlockWriter, DefaultBlockWriter, Linktype};
use std::{
    io::{Error, ErrorKind},
    net::Ipv4Addr,
};
use types::ip::{Ipv4Flags, Ipv4Packet, KIND_IPV4};

#[test]
fn write_sample_ip_packets() -> Result<(), Error> {
    let mut buffer = Vec::new();
    let mut writer = DefaultBlockWriter::<_, &str>::new(&mut buffer, "alice")?;

    writer.add_interface(&"eth0", Linktype::ETHERNET, 4096, vec![])?;

    writer.add_packet(
        &"eth0",
        200,
        [1, 2, 3, 4, 5, 6],
        [6, 5, 4, 3, 2, 1],
        KIND_IPV4,
        &Ipv4Packet {
            dscp: 0,
            enc: 0,
            identification: 0,
            flags: Ipv4Flags {
                df: false,
                mf: false,
            },
            fragment_offset: 0,
            ttl: 64,
            proto: 0,
            src: Ipv4Addr::new(192, 168, 2, 101),
            dst: Ipv4Addr::new(10, 7, 18, 78),
            content: b"Hello world".to_vec(),
        },
        None,
    )?;

    writer.add_packet(
        &"eth0",
        1_200,
        [6, 5, 4, 3, 2, 1],
        [1, 2, 3, 4, 5, 6],
        KIND_IPV4,
        &Ipv4Packet {
            dscp: 0,
            enc: 0,
            identification: 0,
            flags: Ipv4Flags {
                df: false,
                mf: false,
            },
            fragment_offset: 0,
            ttl: 64,
            proto: 0,
            src: Ipv4Addr::new(10, 7, 18, 78),
            dst: Ipv4Addr::new(192, 168, 2, 101),
            content: b"Hello client".to_vec(),
        },
        None,
    )?;

    drop(writer);

    assert_eq!(buffer, SAMPLE_RAW_IP_PACKETS);

    Ok(())
}

#[test]
fn writer_no_such_iface() -> Result<(), Error> {
    let mut buffer = Vec::new();
    let mut writer = DefaultBlockWriter::<_, &str>::new(&mut buffer, "alice")?;

    writer.add_interface(&"eth0", Linktype::ETHERNET, 4096, vec![])?;

    let err = writer
        .add_packet(
            &"eth1",
            200,
            [1, 2, 3, 4, 5, 6],
            [6, 5, 4, 3, 2, 1],
            KIND_IPV4,
            &Ipv4Packet {
                dscp: 0,
                enc: 0,
                identification: 0,
                flags: Ipv4Flags {
                    df: false,
                    mf: false,
                },
                fragment_offset: 0,
                ttl: 64,
                proto: 0,
                src: Ipv4Addr::new(192, 168, 2, 101),
                dst: Ipv4Addr::new(10, 7, 18, 78),
                content: b"Hello world".to_vec(),
            },
            None,
        )
        .unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(err.to_string(), "no such interface registered");

    Ok(())
}

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{FromBytestream, IntoBytestream};

use super::*;

#[test]
fn v4_empty() -> std::io::Result<()> {
    let input = Ipv4Packet {
        dscp: 0b000000,
        enc: 0b00,
        identification: 0,
        flags: Ipv4Flags {
            df: false,
            mf: false,
        },
        fragment_offset: 0,
        ttl: 0,
        proto: 0,
        src: Ipv4Addr::new(1, 2, 3, 4),
        dest: Ipv4Addr::new(9, 8, 7, 6),
        content: Vec::new(),
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv4Packet {
        dscp: 0b010101,
        enc: 0b10,
        identification: 0,
        flags: Ipv4Flags {
            df: true,
            mf: false,
        },
        fragment_offset: 1000,
        ttl: 64,
        proto: 12,
        src: Ipv4Addr::new(14, 22, 13, 24),
        dest: Ipv4Addr::new(97, 8, 71, 61),
        content: Vec::new(),
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv4Packet {
        dscp: 0b111000,
        enc: 0b01,
        identification: 8861,
        flags: Ipv4Flags {
            df: false,
            mf: true,
        },
        fragment_offset: 70,
        ttl: 255,
        proto: 254,
        src: Ipv4Addr::new(111, 2, 3, 4),
        dest: Ipv4Addr::new(255, 255, 255, 255),
        content: Vec::new(),
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv4Packet {
        dscp: 0b000000,
        enc: 0b11,
        identification: 11,
        flags: Ipv4Flags {
            df: false,
            mf: false,
        },
        fragment_offset: 0,
        ttl: 12,
        proto: 43,
        src: Ipv4Addr::new(255, 255, 255, 255),
        dest: Ipv4Addr::new(9, 8, 7, 6),
        content: Vec::new(),
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv4Packet {
        dscp: 0b100001,
        enc: 0b00,
        identification: 0,
        flags: Ipv4Flags { df: true, mf: true },
        fragment_offset: 0,
        ttl: 0,
        proto: 0,
        src: Ipv4Addr::new(1, 2, 3, 4),
        dest: Ipv4Addr::new(9, 8, 7, 6),
        content: Vec::new(),
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    Ok(())
}

#[test]
fn v4_with_content() -> std::io::Result<()> {
    let input = Ipv4Packet {
        dscp: 0b000000,
        enc: 0b00,
        identification: 0,
        flags: Ipv4Flags {
            df: false,
            mf: false,
        },
        fragment_offset: 0,
        ttl: 0,
        proto: 0,
        src: Ipv4Addr::new(1, 2, 3, 4),
        dest: Ipv4Addr::new(9, 8, 7, 6),
        content: vec![1, 2, 3, 3, 4, 5, 6, 6, 7, 2, 7, 6, 1, 5, 5, 4, 1, 3],
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv4Packet {
        dscp: 0b010101,
        enc: 0b10,
        identification: 0,
        flags: Ipv4Flags {
            df: true,
            mf: false,
        },
        fragment_offset: 1000,
        ttl: 64,
        proto: 12,
        src: Ipv4Addr::new(14, 22, 13, 24),
        dest: Ipv4Addr::new(97, 8, 71, 61),
        content: vec![1, 2, 3, 3, 4, 5, 6, 6, 7, 2, 7, 6, 1, 5, 5, 4, 1, 3],
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv4Packet {
        dscp: 0b111000,
        enc: 0b01,
        identification: 8861,
        flags: Ipv4Flags {
            df: false,
            mf: true,
        },
        fragment_offset: 70,
        ttl: 255,
        proto: 254,
        src: Ipv4Addr::new(111, 2, 3, 4),
        dest: Ipv4Addr::new(255, 255, 255, 255),
        content: vec![1; 100],
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv4Packet {
        dscp: 0b000000,
        enc: 0b11,
        identification: 11,
        flags: Ipv4Flags {
            df: false,
            mf: false,
        },
        fragment_offset: 0,
        ttl: 12,
        proto: 43,
        src: Ipv4Addr::new(255, 255, 255, 255),
        dest: Ipv4Addr::new(9, 8, 7, 6),
        content: vec![1; 500],
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv4Packet {
        dscp: 0b100001,
        enc: 0b00,
        identification: 0,
        flags: Ipv4Flags { df: true, mf: true },
        fragment_offset: 0,
        ttl: 0,
        proto: 0,
        src: Ipv4Addr::new(1, 2, 3, 4),
        dest: Ipv4Addr::new(9, 8, 7, 6),
        content: vec![255; 100],
    };

    let output = Ipv4Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    Ok(())
}

#[test]
fn v6_empty() -> std::io::Result<()> {
    let input = Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        next_header: 0,
        hop_limit: 0,

        src: Ipv6Addr::new(1, 2, 3, 4, 5, 16, 7, 7),
        dest: Ipv6Addr::new(9, 8, 17, 16, 4, 5, 6, 7),
        content: Vec::new(),
    };

    let output = Ipv6Packet::from_buffer(dbg!(input.into_buffer()?))?;
    assert_eq!(input, output);

    // panic!();

    let input = Ipv6Packet {
        traffic_class: 43,
        flow_label: 1111,
        next_header: 2,
        hop_limit: 0,

        src: Ipv6Addr::new(1, 12, 3, 4, 1, 5, 6, 71),
        dest: Ipv6Addr::new(9, 8, 171, 6, 4, 1, 6, 7),
        content: Vec::new(),
    };

    let output = Ipv6Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv6Packet {
        traffic_class: 0,
        flow_label: 64599,
        next_header: 88,
        hop_limit: 64,

        src: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 7),
        dest: Ipv6Addr::new(64, 64, 64, 64, 64, 64, 64, 64),
        content: Vec::new(),
    };

    let output = Ipv6Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        next_header: 123,
        hop_limit: 088,

        src: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 7),
        dest: Ipv6Addr::new(9, 8, 7, 6, 4, 5, 6, 7),
        content: Vec::new(),
    };

    let output = Ipv6Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        next_header: 12,
        hop_limit: 64,

        src: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 7),
        dest: Ipv6Addr::new(9, 8, 7, 6, 4, 5, 6, 7),
        content: Vec::new(),
    };

    let output = Ipv6Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    Ok(())
}

#[test]
fn v6_with_content() -> std::io::Result<()> {
    let input = Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        next_header: 0,
        hop_limit: 0,

        src: Ipv6Addr::new(1, 2, 3, 4, 5, 16, 7, 7),
        dest: Ipv6Addr::new(9, 8, 17, 16, 4, 5, 6, 7),
        content: vec![
            1, 2, 3, 5, 6, 4, 4, 134, 1, 241, 21, 3, 123, 123, 123, 12, 3, 12,
        ],
    };

    let output = Ipv6Packet::from_buffer(dbg!(input.into_buffer()?))?;
    assert_eq!(input, output);

    // panic!();

    let input = Ipv6Packet {
        traffic_class: 43,
        flow_label: 1111,
        next_header: 2,
        hop_limit: 0,

        src: Ipv6Addr::new(1, 12, 3, 4, 1, 5, 6, 71),
        dest: Ipv6Addr::new(9, 8, 171, 6, 4, 1, 6, 7),
        content: vec![
            1, 2, 3, 5, 6, 4, 4, 134, 1, 241, 21, 3, 123, 123, 123, 12, 3, 12,
        ],
    };

    let output = Ipv6Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv6Packet {
        traffic_class: 0,
        flow_label: 64599,
        next_header: 88,
        hop_limit: 64,

        src: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 7),
        dest: Ipv6Addr::new(64, 64, 64, 64, 64, 64, 64, 64),
        content: vec![1; 100],
    };

    let output = Ipv6Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        next_header: 123,
        hop_limit: 088,

        src: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 7),
        dest: Ipv6Addr::new(9, 8, 7, 6, 4, 5, 6, 7),
        content: vec![13; 100],
    };

    let output = Ipv6Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    let input = Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        next_header: 12,
        hop_limit: 64,

        src: Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 7),
        dest: Ipv6Addr::new(9, 8, 7, 6, 4, 5, 6, 7),
        content: vec![1; 500],
    };

    let output = Ipv6Packet::from_buffer(input.into_buffer()?)?;
    assert_eq!(input, output);

    Ok(())
}

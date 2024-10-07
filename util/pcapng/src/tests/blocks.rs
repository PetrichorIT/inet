use crate::{
    fDecryptionSecretsBlock, EnhancedPacketBlock, EnhancedPacketOption, EnhancedPacketOptionFlags,
    InterfaceDescriptionBlock, InterfaceDescriptionOption, InterfaceStatisticsBlock,
    InterfaceStatisticsOption, Linktype, NameResolutionBlock, NameResolutionOption,
    NameResolutionRecord, SectionHeaderBlock, SectionHeaderOption, SimplePacketBlock,
};
use bytepack::{FromBytestream, ToBytestream};
use std::{
    fmt::Debug,
    io::Error,
    net::{Ipv4Addr, Ipv6Addr},
};

fn assert_encoding_e2e<T>(values: &[T])
where
    T: FromBytestream<Error = Error>,
    T: ToBytestream<Error = Error>,
    T: PartialEq + Debug,
{
    for value in values {
        let encoded = value.to_vec().expect("encoding failed");
        let mut encoded_for_decoding = encoded.clone();

        let decoded = T::read_from_vec(&mut encoded_for_decoding).expect("decoding failed");
        assert!(
            encoded_for_decoding.is_empty(),
            "decoding left some bytes behind: {:?}",
            encoded_for_decoding
        );
        assert_eq!(*value, decoded, "Value must be equal after encode->decode");

        let reencoded = decoded.to_vec().expect("reencoding failed");
        assert_eq!(encoded, reencoded, "different encodings");
    }
}

#[test]
fn shb_encoding() {
    assert_encoding_e2e(&[
        SectionHeaderBlock {
            version_major: 2,
            version_minor: 42,
            section_len: 4000,
            options: vec![SectionHeaderOption::HardwareName("MyHW".to_string())],
        },
        SectionHeaderBlock {
            version_major: 2,
            version_minor: 42,
            section_len: 4000,
            options: Vec::new(),
        },
    ]);
}

#[test]
fn shb_options_encoding() {
    assert_encoding_e2e(&[
        SectionHeaderOption::HardwareName("MyHW".to_string()),
        SectionHeaderOption::OperatingSystem("My Operating system".to_string()),
        SectionHeaderOption::UserApplication("My user app".to_string()),
    ]);
}

#[test]
fn idb_encoding() {
    assert_encoding_e2e(&[
        InterfaceDescriptionBlock {
            link_type: Linktype::ETHERNET,
            snap_len: 1500,
            options: vec![
                InterfaceDescriptionOption::InterfaceName("eth0".to_string()),
                InterfaceDescriptionOption::Speed(12000),
            ],
        },
        InterfaceDescriptionBlock {
            link_type: Linktype::ETHERNET,
            snap_len: 5000,
            options: Vec::new(),
        },
    ]);
}

#[test]
fn idb_options_encoding() {
    assert_encoding_e2e(&[
        InterfaceDescriptionOption::InterfaceName("eth0".to_string()),
        InterfaceDescriptionOption::InterfaceDescription("Ethernet 0 (TUN2)".to_string()),
        InterfaceDescriptionOption::AddrIpv4(
            Ipv4Addr::new(192, 168, 0, 106),
            Ipv4Addr::new(255, 255, 255, 0),
        ),
        InterfaceDescriptionOption::AddrIpv6(Ipv6Addr::new(0xfe80, 0, 3, 2, 78, 3, 9, 3), 64),
        InterfaceDescriptionOption::Speed(8000),
        InterfaceDescriptionOption::TimeResolution(9),
        InterfaceDescriptionOption::TimeZone(8),
        InterfaceDescriptionOption::Filter(3, "BFS String".to_string()),
        InterfaceDescriptionOption::OperatingSystem("My OS".to_string()),
        InterfaceDescriptionOption::FcsLen(24),
        InterfaceDescriptionOption::TsOffset(24000),
        InterfaceDescriptionOption::Hardware("sim-sim.com".to_string()),
        InterfaceDescriptionOption::TxSpeed(4000),
        InterfaceDescriptionOption::RxSpeed(8000),
    ]);
}

#[test]
fn spb_encoding() {
    assert_encoding_e2e(&[
        SimplePacketBlock {
            org_len: 0,
            data: Vec::new(),
        },
        SimplePacketBlock {
            org_len: 400,
            data: vec![42; 400],
        },
    ]);
}

#[test]
fn nrb_encoding() {
    assert_encoding_e2e(&[
        NameResolutionBlock {
            records: Vec::new(),
            options: vec![NameResolutionOption::DnsName("ns.example.com".to_string())],
        },
        NameResolutionBlock {
            records: vec![
                NameResolutionRecord {
                    addr: Ipv4Addr::new(192, 168, 2, 103).into(),
                    name: "alice".to_string(),
                },
                NameResolutionRecord {
                    addr: Ipv6Addr::new(192, 168, 2, 103, 0, 1, 4, 3).into(),
                    name: "bob".to_string(),
                },
            ],
            options: vec![NameResolutionOption::DnsAddrIpv4(Ipv4Addr::new(
                10, 1, 1, 0,
            ))],
        },
        NameResolutionBlock {
            records: vec![NameResolutionRecord {
                addr: Ipv6Addr::new(80, 1, 2, 2, 0, 13, 43, 33).into(),
                name: "eve".to_string(),
            }],
            options: Vec::new(),
        },
    ]);
}

#[test]
fn nrb_record_encoding() {
    assert_encoding_e2e(&[
        NameResolutionRecord {
            addr: Ipv4Addr::new(192, 168, 2, 103).into(),
            name: "alice".to_string(),
        },
        NameResolutionRecord {
            addr: Ipv6Addr::new(192, 168, 2, 103, 0, 1, 4, 3).into(),
            name: "bob".to_string(),
        },
    ]);
}

#[test]
fn nrb_option_encoding() {
    assert_encoding_e2e(&[
        NameResolutionOption::DnsName("a.b.c.de".to_string()),
        NameResolutionOption::DnsAddrIpv4(Ipv4Addr::new(9, 1, 2, 4)),
        NameResolutionOption::DnsAddrIpv6(Ipv6Addr::new(8, 7, 32, 329, 3, 3, 123, 3232)),
    ]);
}

#[test]
fn isb_encoding() {
    assert_encoding_e2e(&[
        InterfaceStatisticsBlock {
            interface_id: 1,
            ts: 17000032,
            options: vec![InterfaceStatisticsOption::RecvCount(123)],
        },
        InterfaceStatisticsBlock {
            interface_id: 14,
            ts: 1700003212312,
            options: Vec::new(),
        },
    ]);
}

#[test]
fn isb_option_encoding() {
    assert_encoding_e2e(&[
        InterfaceStatisticsOption::StartTime(4000),
        InterfaceStatisticsOption::EndTime(19000),
        InterfaceStatisticsOption::RecvCount(1024),
        InterfaceStatisticsOption::DropOs(100),
        InterfaceStatisticsOption::AcceptFilter(4000),
        InterfaceStatisticsOption::DropOs(8),
        InterfaceStatisticsOption::Delivered(8000),
    ]);
}

#[test]
fn epb_encoding() {
    assert_encoding_e2e(&[
        EnhancedPacketBlock {
            interface_id: 2,
            ts: 1600,
            org_len: 1400,
            data: vec![1, 2, 3, 4, 5],
            options: vec![EnhancedPacketOption::Flags(EnhancedPacketOptionFlags::all())],
        },
        EnhancedPacketBlock {
            interface_id: 2,
            ts: 1600,
            org_len: 1400,
            data: vec![1, 2, 3, 4, 5],
            options: Vec::new(),
        },
    ]);
}

#[test]
fn epb_options_encoding() {
    assert_encoding_e2e(&[
        EnhancedPacketOption::Flags(EnhancedPacketOptionFlags::all()),
        EnhancedPacketOption::Hash(vec![1, 2, 3, 4]),
        EnhancedPacketOption::DropCount(4),
        EnhancedPacketOption::PacketId(1),
        EnhancedPacketOption::Queue(1),
        EnhancedPacketOption::Verdict(vec![4, 2, 0]),
    ]);
}

#[test]
fn dsb_encoding() {
    assert_encoding_e2e(&[
        DecryptionSecretsBlock {
            secrets_typ: 0x001,
            secrets_data: vec![1, 2, 3, 4],
        },
        DecryptionSecretsBlock {
            secrets_typ: 0x00144,
            secrets_data: vec![1, 2, 3, 4, 5],
        },
    ]);
}

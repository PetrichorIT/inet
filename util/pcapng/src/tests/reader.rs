use std::io::{Cursor, Error, ErrorKind};

use bytepack::FromBytestream;

use crate::{
    Block, BlockReader, EnhancedPacketBlock, InterfaceDescriptionBlock, InterfaceDescriptionOption,
    Linktype, SectionHeaderBlock, SectionHeaderOption,
};

use super::{SAMPLE_HTTP_GET, SAMPLE_RAW_IP_PACKETS};

#[test]
fn read_existing_files() -> Result<(), Error> {
    for file in [SAMPLE_HTTP_GET, SAMPLE_RAW_IP_PACKETS] {
        let mut slice: &[u8] = file;
        while !slice.is_empty() {
            let _block = Block::read_from_slice(&mut slice)?;
        }
    }
    Ok(())
}

#[test]
fn read_in_order() -> Result<(), Error> {
    let reader = BlockReader::new(Cursor::new(SAMPLE_HTTP_GET));

    let n = reader.into_iter().count();
    assert_eq!(n, 18);

    Ok(())
}

#[test]
fn read_backwards() -> Result<(), Error> {
    let mut reader = BlockReader::new(Cursor::new(SAMPLE_HTTP_GET));

    for _ in 0..3 {
        let _ = reader.next();
    }

    assert_eq!(
        reader
            .next_back()
            .ok_or(Error::new(ErrorKind::Other, "no element"))??,
        Block::EnhancedPacketBlock(EnhancedPacketBlock {
            interface_id: 0,
            ts: 0,
            org_len: 14,
            data: vec![0; 14],
            options: vec![]
        })
    );

    assert_eq!(
        reader
            .next_back()
            .ok_or(Error::new(ErrorKind::Other, "no element"))??,
        Block::InterfaceDescriptionBlock(InterfaceDescriptionBlock {
            link_type: Linktype::ETHERNET,
            snap_len: 4098, // < should be 4096, but hey
            options: vec![
                InterfaceDescriptionOption::InterfaceName("en0 (en0)".to_string()),
                InterfaceDescriptionOption::InterfaceDescription("en0 (en0) @ NetworkDevice { addr: MacAddress([244, 133, 135, 154, 148, 69]), inner: EthernetDevice { output: Gate { path: \"client.port\" }, input: Gate { path: \"client.port\" }, channel: Some(Channel { metrics: ChannelMetrics { bitrate: 1000000, latency: 50ms, jitter: 0ns, drop_behaviour: Queue(Some(0)) }, state: Idle }) } }".to_string())
            ]
        })
    );

    let shb = Block::SectionHeaderBlock(SectionHeaderBlock {
        version_major: 1,
        version_minor: 0,
        section_len: 0xffff_ffff_ffff_ffff,
        options: vec![
            SectionHeaderOption::HardwareName("(des/inet) simulated node :: client".to_string()),
            SectionHeaderOption::OperatingSystem("des/inet".to_string()),
        ],
    });
    assert_eq!(
        reader
            .next_back()
            .ok_or(Error::new(ErrorKind::Other, "no element"))??,
        shb
    );

    assert!(reader.next_back().is_none());
    assert!(reader.next_back().is_none());

    assert_eq!(
        reader
            .next()
            .ok_or(Error::new(ErrorKind::Other, "no element"))??,
        shb
    );

    Ok(())
}

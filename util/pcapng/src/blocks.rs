use bitflags::bitflags;
use bytepack::{BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt, LE};
use std::{
    io::{Cursor, Error, ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::linktype::Linktype;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    SectionHeaderBlock(SectionHeaderBlock),
    InterfaceDescriptionBlock(InterfaceDescriptionBlock),
    SimplePacketBlock(SimplePacketBlock),
    NameResolutionBlock(NameResolutionBlock),
    InterfaceStatisticsBlock(InterfaceStatisticsBlock),
    EnhancedPacketBlock(EnhancedPacketBlock),
    DecryptionSecretsBlock(DecryptionSecretsBlock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeaderBlock {
    pub version_major: u16,
    pub version_minor: u16,
    pub section_len: u64,
    pub options: Vec<SectionHeaderOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionHeaderOption {
    HardwareName(String),
    OperatingSystem(String),
    UserApplication(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDescriptionBlock {
    pub link_type: Linktype,
    pub snap_len: u32,
    pub options: Vec<InterfaceDescriptionOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceDescriptionOption {
    InterfaceName(String),
    InterfaceDescription(String),
    AddrIpv4(Ipv4Addr, Ipv4Addr),
    AddrIpv6(Ipv6Addr, u8),
    // MAC
    // EUI
    Speed(u64),
    TimeResolution(u8),
    TimeZone(u32),
    Filter(u8, String),
    OperatingSystem(String),
    FcsLen(u8),
    TsOffset(u64),
    Hardware(String),
    TxSpeed(u64),
    RxSpeed(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplePacketBlock {
    pub org_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameResolutionBlock {
    pub records: Vec<NameResolutionRecord>,
    pub options: Vec<NameResolutionOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameResolutionRecord {
    pub addr: IpAddr,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameResolutionOption {
    DnsName(String),
    DnsAddrIpv4(Ipv4Addr),
    DnsAddrIpv6(Ipv6Addr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceStatisticsBlock {
    pub interface_id: u32,
    pub ts: u64,
    pub options: Vec<InterfaceStatisticsOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceStatisticsOption {
    StartTime(u64),
    EndTime(u64),
    RecvCount(u64),
    DropCount(u64),
    AcceptFilter(u64),
    DropOs(u64),
    Delivered(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnhancedPacketBlock {
    pub interface_id: u32,
    pub ts: u64,
    pub org_len: u32,
    pub data: Vec<u8>,
    pub options: Vec<EnhancedPacketOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnhancedPacketOption {
    Flags(EnhancedPacketOptionFlags),
    Hash(Vec<u8>),
    DropCount(u64),
    PacketId(u64),
    Queue(u32),
    Verdict(Vec<u8>),
}

bitflags! {
    pub struct EnhancedPacketOptionFlags: u32 {
        const INBOUND       = 0b01;
        const OUTBOUND      = 0b10;
        const UNICAST       = 0b00100;
        const MULTICAST     = 0b01000;
        const BROADCAST     = Self::UNICAST.bits | Self::MULTICAST.bits;
        const PROMISCUOUS   = 0b10000;
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionSecretsBlock {
    pub secrets_typ: u32,
    pub secrets_data: Vec<u8>,
    // NO DSB specific options are defined
}

const BLOCK_TYP_SHB: u32 = 0x0A0D0D0A;
const BLOCK_TYP_IHB: u32 = 0x00000001;
const BLOCK_TYP_SPB: u32 = 0x00000003;
const BLOCK_TYP_NRB: u32 = 0x00000004;
const BLOCK_TYP_ISB: u32 = 0x00000005;
const BLOCK_TYP_EPB: u32 = 0x00000006;
const BLOCK_TYP_DSB: u32 = 0x0000000A;

const SHB_MAGIC: u32 = 0x1A2B3C4D;

const SHB_OPTION_HW_NAME: u16 = 0x02;
const SHB_OPTION_OS_NAME: u16 = 0x03;
const SHB_OPTION_USER_APPLICATION: u16 = 0x04;

const IDB_OPTION_IFACE_NAME: u16 = 0x02;
const IDB_OPTION_IFACE_DESC: u16 = 0x03;
const IDB_OPTION_ADDR_IPV4: u16 = 0x04;
const IDB_OPTION_ADDR_IPV6: u16 = 0x05;
const IDB_OPTION_ADDR_MAC: u16 = 0x06;
const IDB_OPTION_ADDR_EUI: u16 = 0x07;
const IDB_OPTION_SPEED: u16 = 0x07;
const IDB_OPTION_TIME_RESOL: u16 = 0x09;
const IDB_OPTION_TIME_ZONE: u16 = 0x0A;
const IDB_OPTION_FILTER: u16 = 0x0B;
const IDB_OPTION_OS: u16 = 0x0C;
const IDB_OPTION_FSC_LEN: u16 = 0x0D;
const IDB_OPTION_TS_OFFSET: u16 = 0x0E;
const IDB_OPTION_HARDWARE: u16 = 0x0F;
const IDB_OPTION_TX_SPEED: u16 = 0x10;
const IDB_OPTION_RX_SPEED: u16 = 0x11;

const NRB_RECORD_IPV4: u16 = 0x0001;
const NRB_RECORD_IPV6: u16 = 0x0002;

const NRB_OPTION_DNS_NAME: u16 = 0x02;
const NRB_OPTION_ADDR_IPV4: u16 = 0x03;
const NRB_OPTION_ADDR_IPV6: u16 = 0x04;

const ISB_OPTION_START_TIME: u16 = 0x02;
const ISB_OPTION_END_TIME: u16 = 0x03;
const ISB_OPTION_RECV_COUNT: u16 = 0x04;
const ISB_OPTION_DROP_COUNT: u16 = 0x05;
const ISB_OPTION_ACCEPT_FILTER: u16 = 0x06;
const ISB_OPTION_OS_DROP: u16 = 0x07;
const ISB_OPTION_DELIVERED: u16 = 0x08;

const EPB_OPTION_FLAGS: u16 = 0x02;
const EPB_OPTION_HASH: u16 = 0x03;
const EPB_OPTION_DROP_COUNT: u16 = 0x04;
const EPB_OPTION_PACKET_ID: u16 = 0x05;
const EPB_OPTION_QUEUE: u16 = 0x06;
const EPB_OPTION_VERDICT: u16 = 0x07;

//
// # ToBytestream
//

impl ToBytestream for Block {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::SectionHeaderBlock(shb) => shb.to_bytestream(stream),
            Self::InterfaceDescriptionBlock(idb) => idb.to_bytestream(stream),
            Self::SimplePacketBlock(spb) => spb.to_bytestream(stream),
            Self::NameResolutionBlock(nrb) => nrb.to_bytestream(stream),
            Self::InterfaceStatisticsBlock(isb) => isb.to_bytestream(stream),
            Self::EnhancedPacketBlock(epb) => epb.to_bytestream(stream),
            Self::DecryptionSecretsBlock(dsb) => dsb.to_bytestream(stream),
        }
    }
}

impl ToBytestream for SectionHeaderBlock {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_SHB, |stream| {
            stream.write_u32::<LE>(SHB_MAGIC)?;
            stream.write_u16::<LE>(self.version_major)?;
            stream.write_u16::<LE>(self.version_minor)?;
            stream.write_u64::<LE>(self.section_len)?;

            write_options(stream, &self.options)?;

            Ok(())
        })
    }
}

impl ToBytestream for SectionHeaderOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        match self {
            Self::HardwareName(ref string) => write_option(stream, SHB_OPTION_HW_NAME, |stream| {
                stream.write_all(string.as_bytes())?;
                Ok(())
            }),
            Self::OperatingSystem(ref string) => {
                write_option(stream, SHB_OPTION_OS_NAME, |stream| {
                    stream.write_all(string.as_bytes())?;
                    Ok(())
                })
            }

            Self::UserApplication(ref string) => {
                write_option(stream, SHB_OPTION_USER_APPLICATION, |stream| {
                    stream.write_all(string.as_bytes())?;
                    Ok(())
                })
            }
        }
    }
}

impl ToBytestream for InterfaceDescriptionBlock {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_IHB, |stream| {
            stream.write_u16::<LE>(self.link_type.0)?;
            stream.write_u16::<LE>(0)?;
            stream.write_u32::<LE>(self.snap_len)?;

            write_options(stream, &self.options)?;

            Ok(())
        })
    }
}

impl ToBytestream for InterfaceDescriptionOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        match self {
            Self::InterfaceName(ref name) => {
                write_option(stream, IDB_OPTION_IFACE_NAME, |stream| {
                    stream.write_all(name.as_bytes())
                })
            }
            Self::InterfaceDescription(ref name) => {
                write_option(stream, IDB_OPTION_IFACE_DESC, |stream| {
                    stream.write_all(name.as_bytes())
                })
            }
            Self::AddrIpv4(addr, mask) => write_option(stream, IDB_OPTION_ADDR_IPV4, |stream| {
                addr.to_bytestream(stream)?;
                mask.to_bytestream(stream)
            }),
            Self::AddrIpv6(addr, prefix_len) => {
                write_option(stream, IDB_OPTION_ADDR_IPV6, |stream| {
                    addr.to_bytestream(stream)?;
                    stream.write_u8(*prefix_len)
                })
            }
            // MAC
            // EUI
            Self::Speed(speed) => write_option(stream, IDB_OPTION_SPEED, |stream| {
                stream.write_u64::<LE>(*speed)
            }),
            Self::TimeResolution(precision) => {
                write_option(stream, IDB_OPTION_TIME_RESOL, |stream| {
                    stream.write_u8(*precision)
                })
            }
            Self::TimeZone(time_zone) => write_option(stream, IDB_OPTION_TIME_ZONE, |stream| {
                stream.write_u32::<LE>(*time_zone)
            }),
            Self::Filter(ref kind, ref filter) => {
                write_option(stream, IDB_OPTION_FILTER, |stream| {
                    stream.write(&[*kind])?;
                    stream.write_all(filter.as_bytes())
                })
            }
            Self::OperatingSystem(ref name) => write_option(stream, IDB_OPTION_OS, |stream| {
                stream.write_all(name.as_bytes())
            }),
            Self::FcsLen(len) => {
                write_option(stream, IDB_OPTION_FSC_LEN, |stream| stream.write_u8(*len))
            }
            Self::TsOffset(offset) => write_option(stream, IDB_OPTION_TS_OFFSET, |stream| {
                stream.write_u64::<LE>(*offset)
            }),
            Self::Hardware(hw) => write_option(stream, IDB_OPTION_HARDWARE, |stream| {
                stream.write_all(hw.as_bytes())
            }),
            Self::TxSpeed(speed) => write_option(stream, IDB_OPTION_TX_SPEED, |stream| {
                stream.write_u64::<LE>(*speed)
            }),
            Self::RxSpeed(speed) => write_option(stream, IDB_OPTION_RX_SPEED, |stream| {
                stream.write_u64::<LE>(*speed)
            }),
        }
    }
}

impl ToBytestream for SimplePacketBlock {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_SPB, |stream| {
            stream.write_u32::<LE>(self.org_len)?;
            stream.write_all(&self.data)
        })
    }
}

impl ToBytestream for NameResolutionBlock {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_NRB, |stream| {
            write_options(stream, &self.records)?;
            write_options(stream, &self.options)
        })
    }
}

impl ToBytestream for NameResolutionRecord {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        let kind = if self.addr.is_ipv4() {
            NRB_RECORD_IPV4
        } else {
            NRB_RECORD_IPV6
        };

        write_option(stream, kind, |stream| {
            self.addr.to_bytestream(stream)?;
            stream.write_all(self.name.as_bytes())?;
            stream.write_all(&[0])
        })
    }
}

impl ToBytestream for NameResolutionOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::DnsName(name) => write_option(stream, NRB_OPTION_DNS_NAME, |stream| {
                stream.write_all(name.as_bytes())
            }),
            Self::DnsAddrIpv4(v4) => write_option(stream, NRB_OPTION_ADDR_IPV4, |stream| {
                v4.to_bytestream(stream)
            }),
            Self::DnsAddrIpv6(v6) => write_option(stream, NRB_OPTION_ADDR_IPV6, |stream| {
                v6.to_bytestream(stream)
            }),
        }
    }
}

impl ToBytestream for InterfaceStatisticsBlock {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_ISB, |stream| {
            stream.write_u32::<LE>(self.interface_id)?;

            let mut bytes = Cursor::new(self.ts.to_be_bytes());
            let upper = bytes.read_u32::<LE>()?;
            let lower = bytes.read_u32::<LE>()?;
            stream.write_all(&upper.to_be_bytes())?;
            stream.write_all(&lower.to_be_bytes())?;

            write_options(stream, &self.options)
        })
    }
}

impl ToBytestream for InterfaceStatisticsOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::StartTime(value) => write_option(stream, ISB_OPTION_START_TIME, |stream| {
                stream.write_u64::<LE>(*value)
            }),
            Self::EndTime(value) => write_option(stream, ISB_OPTION_END_TIME, |stream| {
                stream.write_u64::<LE>(*value)
            }),
            Self::RecvCount(value) => write_option(stream, ISB_OPTION_RECV_COUNT, |stream| {
                stream.write_u64::<LE>(*value)
            }),
            Self::DropCount(value) => write_option(stream, ISB_OPTION_DROP_COUNT, |stream| {
                stream.write_u64::<LE>(*value)
            }),
            Self::AcceptFilter(value) => write_option(stream, ISB_OPTION_ACCEPT_FILTER, |stream| {
                stream.write_u64::<LE>(*value)
            }),
            Self::DropOs(value) => write_option(stream, ISB_OPTION_OS_DROP, |stream| {
                stream.write_u64::<LE>(*value)
            }),
            Self::Delivered(value) => write_option(stream, ISB_OPTION_DELIVERED, |stream| {
                stream.write_u64::<LE>(*value)
            }),
        }
    }
}

impl ToBytestream for EnhancedPacketBlock {
    type Error = Error;

    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> std::result::Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_EPB, |stream| {
            stream.write_u32::<LE>(self.interface_id)?;

            let mut bytes = Cursor::new(self.ts.to_be_bytes());
            let upper = bytes.read_u32::<LE>()?;
            let lower = bytes.read_u32::<LE>()?;
            stream.write_all(&upper.to_be_bytes())?;
            stream.write_all(&lower.to_be_bytes())?;

            stream.write_u32::<LE>(self.data.len() as u32)?;
            stream.write_u32::<LE>(self.org_len)?;

            let data_pad = (4 - (self.data.len() % 4)) % 4;

            stream.write_all(&self.data)?;
            stream.write_all(&vec![0u8; data_pad])?;

            write_options(stream, &self.options)?;

            Ok(())
        })
    }
}

impl ToBytestream for EnhancedPacketOption {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::Flags(flags) => write_option(stream, EPB_OPTION_FLAGS, |stream| {
                stream.write_u32::<LE>(flags.bits)
            }),
            Self::Hash(hash) => {
                write_option(stream, EPB_OPTION_HASH, |stream| stream.write_all(hash))
            }
            Self::DropCount(drop_count) => write_option(stream, EPB_OPTION_DROP_COUNT, |stream| {
                stream.write_u64::<LE>(*drop_count)
            }),
            Self::PacketId(pkt_id) => write_option(stream, EPB_OPTION_PACKET_ID, |stream| {
                stream.write_u64::<LE>(*pkt_id)
            }),
            Self::Queue(queue_id) => write_option(stream, EPB_OPTION_QUEUE, |stream| {
                stream.write_u32::<LE>(*queue_id)
            }),
            Self::Verdict(verdict) => write_option(stream, EPB_OPTION_VERDICT, |stream| {
                stream.write_all(verdict)
            }),
        }
    }
}

impl ToBytestream for DecryptionSecretsBlock {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        write_block(stream, BLOCK_TYP_DSB, |stream| {
            stream.write_u32::<LE>(self.secrets_typ)?;
            stream.write_u32::<LE>(self.secrets_data.len() as u32)?;
            stream.write_all(&self.secrets_data)?;

            let pad = (4 - (self.secrets_data.len() % 4)) % 4;
            stream.write_all(&vec![0; pad])
        })
    }
}

fn write_block(
    stream: &mut bytepack::BytestreamWriter,
    block_typ: u32,
    f: impl FnOnce(&mut bytepack::BytestreamWriter) -> Result<(), Error>,
) -> Result<(), Error> {
    stream.write_u32::<LE>(block_typ)?;
    let len_marker = stream.create_typed_marker::<u32>()?;
    f(stream)?;

    let block_len = stream.len_since_marker(&len_marker) as u32 + 12;
    stream
        .update_marker(&len_marker)
        .write_u32::<LE>(block_len)?;
    stream.write_u32::<LE>(block_len)?;

    Ok(())
}

fn write_options<T: ToBytestream<Error = Error>>(
    stream: &mut bytepack::BytestreamWriter,
    options: &[T],
) -> Result<(), Error> {
    for option in options {
        option.to_bytestream(stream)?;
    }
    // EOO
    stream.write_u32::<LE>(0)?;
    Ok(())
}

fn write_option(
    stream: &mut bytepack::BytestreamWriter,
    option_typ: u16,
    f: impl FnOnce(&mut bytepack::BytestreamWriter) -> Result<(), Error>,
) -> Result<(), Error> {
    stream.write_u16::<LE>(option_typ)?;
    let marker = stream.create_typed_marker::<u16>()?;
    f(stream)?;

    let len = stream.len_since_marker(&marker) as u16;
    stream.update_marker(&marker).write_u16::<LE>(len)?;

    let pad = (4 - (len % 4)) % 4;
    stream.write_all(&vec![0x00; pad as usize])?;

    Ok(())
}

//
// # FromBytestream
//

impl FromBytestream for Block {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        let block_type = stream.read_u32::<LE>()?;
        stream.bump_back(4);

        Ok(match block_type {
            BLOCK_TYP_SHB => Self::SectionHeaderBlock(SectionHeaderBlock::from_bytestream(stream)?),
            BLOCK_TYP_IHB => {
                Self::InterfaceDescriptionBlock(InterfaceDescriptionBlock::from_bytestream(stream)?)
            }
            BLOCK_TYP_NRB => {
                Self::NameResolutionBlock(NameResolutionBlock::from_bytestream(stream)?)
            }
            BLOCK_TYP_ISB => {
                Self::InterfaceStatisticsBlock(InterfaceStatisticsBlock::from_bytestream(stream)?)
            }
            BLOCK_TYP_EPB => {
                Self::EnhancedPacketBlock(EnhancedPacketBlock::from_bytestream(stream)?)
            }
            BLOCK_TYP_DSB => {
                Self::DecryptionSecretsBlock(DecryptionSecretsBlock::from_bytestream(stream)?)
            }
            _ => unreachable!(),
        })
    }
}

impl FromBytestream for SectionHeaderBlock {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_SHB, |body| {
            let byteorder_magic = body.read_u32::<LE>()?;
            assert_eq!(byteorder_magic, SHB_MAGIC);
            let version_major = body.read_u16::<LE>()?;
            let version_minor = body.read_u16::<LE>()?;
            let section_len = body.read_u64::<LE>()?;
            let options = read_options::<SectionHeaderOption>(body)?;

            Ok(SectionHeaderBlock {
                section_len,
                version_major,
                version_minor,
                options,
            })
        })
    }
}

impl FromBytestream for SectionHeaderOption {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_option(stream, |typ, body| {
            Ok(match typ {
                SHB_OPTION_HW_NAME => {
                    let mut str = String::new();
                    body.read_to_string(&mut str)?;
                    Self::HardwareName(str)
                }
                SHB_OPTION_OS_NAME => {
                    let mut str = String::new();
                    body.read_to_string(&mut str)?;
                    Self::OperatingSystem(str)
                }
                SHB_OPTION_USER_APPLICATION => {
                    let mut str = String::new();
                    body.read_to_string(&mut str)?;
                    Self::UserApplication(str)
                }
                _ => todo!("{typ}"),
            })
        })
    }
}

impl FromBytestream for InterfaceDescriptionBlock {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_IHB, |body| {
            let link_type = Linktype(body.read_u16::<LE>()?);
            let resv = body.read_u16::<LE>()?;
            assert_eq!(resv, 0);
            let snap_len = body.read_u32::<LE>()?;
            let options = read_options::<InterfaceDescriptionOption>(body)?;

            Ok(InterfaceDescriptionBlock {
                link_type,
                snap_len,
                options,
            })
        })
    }
}

impl FromBytestream for InterfaceDescriptionOption {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_option(stream, |typ, body| {
            Ok(match typ {
                IDB_OPTION_IFACE_NAME => {
                    let mut str = String::new();
                    body.read_to_string(&mut str)?;
                    Self::InterfaceName(str)
                }
                IDB_OPTION_IFACE_DESC => {
                    let mut str = String::new();
                    body.read_to_string(&mut str)?;
                    Self::InterfaceDescription(str)
                }
                IDB_OPTION_ADDR_IPV4 => Self::AddrIpv4(
                    Ipv4Addr::from_bytestream(body)?,
                    Ipv4Addr::from_bytestream(body)?,
                ),

                IDB_OPTION_ADDR_IPV6 => {
                    Self::AddrIpv6(Ipv6Addr::from_bytestream(body)?, body.read_u8()?)
                }
                // MAC
                // EUI
                IDB_OPTION_SPEED => Self::Speed(body.read_u64::<LE>()?),
                IDB_OPTION_TIME_RESOL => Self::TimeResolution(body.read_u8()?),
                IDB_OPTION_TIME_ZONE => Self::TimeZone(body.read_u32::<LE>()?),
                IDB_OPTION_FILTER => {
                    let kind = body.read_u8()?;
                    let mut str = String::new();
                    body.read_to_string(&mut str)?;
                    Self::Filter(kind, str)
                }
                IDB_OPTION_OS => {
                    let mut str = String::new();
                    body.read_to_string(&mut str)?;
                    Self::OperatingSystem(str)
                }
                IDB_OPTION_FSC_LEN => Self::FcsLen(body.read_u8()?),
                IDB_OPTION_TS_OFFSET => Self::TsOffset(body.read_u64::<LE>()?),
                IDB_OPTION_HARDWARE => {
                    let mut str = String::new();
                    body.read_to_string(&mut str)?;
                    Self::Hardware(str)
                }
                IDB_OPTION_TX_SPEED => Self::TxSpeed(body.read_u64::<LE>()?),
                IDB_OPTION_RX_SPEED => Self::RxSpeed(body.read_u64::<LE>()?),
                _ => todo!("{typ}"),
            })
        })
    }
}

impl FromBytestream for SimplePacketBlock {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_SPB, |body| {
            let org_len = body.read_u32::<LE>()?;
            let mut data = Vec::new();
            body.read_to_end(&mut data)?;
            Ok(SimplePacketBlock { org_len, data })
        })
    }
}

impl FromBytestream for NameResolutionBlock {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_NRB, |body| {
            let records = read_options::<NameResolutionRecord>(body)?;
            let options = read_options::<NameResolutionOption>(body)?;
            Ok(NameResolutionBlock { records, options })
        })
    }
}

impl FromBytestream for NameResolutionRecord {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_option(stream, |typ, body| {
            let addr = match typ {
                0 => return Err(Error::new(ErrorKind::UnexpectedEof, "EOR")),
                NRB_RECORD_IPV4 => Ipv4Addr::from_bytestream(body)?.into(),
                NRB_RECORD_IPV6 => Ipv6Addr::from_bytestream(body)?.into(),
                _ => unreachable!(),
            };
            let mut name = String::new();
            body.read_to_string(&mut name)?;
            assert!(name.ends_with('\0'));
            name.pop();

            Ok(NameResolutionRecord { addr, name })
        })
    }
}

impl FromBytestream for NameResolutionOption {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_option(stream, |typ, body| match typ {
            NRB_OPTION_DNS_NAME => {
                let mut str = String::new();
                body.read_to_string(&mut str)?;
                Ok(Self::DnsName(str))
            }
            NRB_OPTION_ADDR_IPV4 => Ok(Self::DnsAddrIpv4(Ipv4Addr::from_bytestream(body)?)),
            NRB_OPTION_ADDR_IPV6 => Ok(Self::DnsAddrIpv6(Ipv6Addr::from_bytestream(body)?)),
            _ => unreachable!("typ = {typ}"),
        })
    }
}

impl FromBytestream for InterfaceStatisticsBlock {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_ISB, |body| {
            let interface_id = body.read_u32::<LE>()?;

            let upper = body.read_u32::<LE>()?.to_be_bytes();
            let lower = body.read_u32::<LE>()?.to_be_bytes();
            let ts = u64::from_be_bytes([
                upper[0], upper[1], upper[2], upper[3], lower[0], lower[1], lower[2], lower[3],
            ]);

            let options = read_options::<InterfaceStatisticsOption>(body)?;

            Ok(InterfaceStatisticsBlock {
                interface_id,
                ts,
                options,
            })
        })
    }
}

impl FromBytestream for InterfaceStatisticsOption {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_option(stream, |typ, body| match typ {
            ISB_OPTION_START_TIME => Ok(Self::StartTime(body.read_u64::<LE>()?)),
            ISB_OPTION_END_TIME => Ok(Self::EndTime(body.read_u64::<LE>()?)),
            ISB_OPTION_RECV_COUNT => Ok(Self::RecvCount(body.read_u64::<LE>()?)),
            ISB_OPTION_DROP_COUNT => Ok(Self::DropCount(body.read_u64::<LE>()?)),
            ISB_OPTION_ACCEPT_FILTER => Ok(Self::AcceptFilter(body.read_u64::<LE>()?)),
            ISB_OPTION_OS_DROP => Ok(Self::DropOs(body.read_u64::<LE>()?)),
            ISB_OPTION_DELIVERED => Ok(Self::Delivered(body.read_u64::<LE>()?)),
            _ => unreachable!("typ = {typ}"),
        })
    }
}

impl FromBytestream for EnhancedPacketBlock {
    type Error = Error;

    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_EPB, |body| {
            let interface_id = body.read_u32::<LE>()?;

            let upper = body.read_u32::<LE>()?.to_be_bytes();
            let lower = body.read_u32::<LE>()?.to_be_bytes();
            let ts = u64::from_be_bytes([
                upper[0], upper[1], upper[2], upper[3], lower[0], lower[1], lower[2], lower[3],
            ]);

            let cap_len = body.read_u32::<LE>()?;
            let org_len = body.read_u32::<LE>()?;

            let mut data_stream = body.extract(cap_len as usize)?;
            let mut data = Vec::new();
            data_stream.read_to_end(&mut data)?;

            let pad = (4 - (cap_len % 4)) % 4;
            body.read_exact(&mut vec![0; pad as usize])?;

            let options = read_options::<EnhancedPacketOption>(body)?;

            Ok(EnhancedPacketBlock {
                interface_id,
                ts,
                org_len,
                data,
                options,
            })
        })
    }
}

impl FromBytestream for EnhancedPacketOption {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_option(stream, |typ, body| {
            Ok(match typ {
                EPB_OPTION_FLAGS => Self::Flags(
                    EnhancedPacketOptionFlags::from_bits(body.read_u32::<LE>()?).unwrap(),
                ),
                EPB_OPTION_HASH => {
                    let mut vec = Vec::new();
                    body.read_to_end(&mut vec)?;
                    Self::Hash(vec)
                }
                EPB_OPTION_DROP_COUNT => Self::DropCount(body.read_u64::<LE>()?),
                EPB_OPTION_PACKET_ID => Self::PacketId(body.read_u64::<LE>()?),
                EPB_OPTION_QUEUE => Self::Queue(body.read_u32::<LE>()?),
                EPB_OPTION_VERDICT => {
                    let mut vec = Vec::new();
                    body.read_to_end(&mut vec)?;
                    Self::Verdict(vec)
                }
                _ => unreachable!("typ = {typ}"),
            })
        })
    }
}

impl FromBytestream for DecryptionSecretsBlock {
    type Error = Error;
    fn from_bytestream(stream: &mut bytepack::BytestreamReader) -> Result<Self, Self::Error> {
        read_block(stream, BLOCK_TYP_DSB, |body| {
            let secrets_typ = body.read_u32::<LE>()?;
            let len = body.read_u32::<LE>()? as usize;

            let mut data_stream = body.extract(len)?;
            let mut secrets_data = Vec::new();
            data_stream.read_to_end(&mut secrets_data)?;

            let pad = (4 - (len % 4)) % 4;
            body.read_exact(&mut vec![0; pad])?;

            Ok(DecryptionSecretsBlock {
                secrets_typ,
                secrets_data,
            })
        })
    }
}

fn read_block<R>(
    stream: &mut bytepack::BytestreamReader,
    block_typ: u32,
    f: impl FnOnce(&mut bytepack::BytestreamReader) -> Result<R, Error>,
) -> Result<R, Error> {
    let read_block_typ = stream.read_u32::<LE>()?;
    if read_block_typ != block_typ {
        return Err(Error::new(ErrorKind::InvalidInput, "unexpected block typ"));
    }

    let block_len = stream.read_u32::<LE>()?;
    let pad = block_len % 4;
    let mut body = stream.extract((block_len + pad - 12) as usize)?;

    let result = f(&mut body);

    let block_len_redundant = stream.read_u32::<LE>()?;
    if block_len != block_len_redundant {
        return Err(Error::new(ErrorKind::Other, "total block len error"));
    }

    result
}

fn read_options<T: FromBytestream<Error = Error>>(
    stream: &mut bytepack::BytestreamReader,
) -> Result<Vec<T>, Error> {
    let mut options = Vec::new();
    while !stream.is_empty() {
        match T::from_bytestream(stream) {
            Ok(v) => options.push(v),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(options)
}

fn read_option<R>(
    stream: &mut bytepack::BytestreamReader,
    f: impl FnOnce(u16, &mut bytepack::BytestreamReader) -> Result<R, Error>,
) -> Result<R, Error> {
    let typ = stream.read_u16::<LE>()?;
    let len = stream.read_u16::<LE>()?;

    if typ == 0 && len == 0 {
        return Err(Error::new(ErrorKind::UnexpectedEof, "EOO"));
    }

    let mut body = stream.extract(len as usize)?;
    let result = f(typ, &mut body)?;

    let pad = (4 - (len % 4)) % 4;
    stream.read_exact(&mut vec![0; pad as usize])?;
    Ok(result)
}

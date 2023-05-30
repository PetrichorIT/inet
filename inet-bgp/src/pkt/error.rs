use std::io::{Error, ErrorKind};

use bytepack::{
    raw_enum, ByteOrder, BytestreamReader, BytestreamWriter, FromBytestream, StreamReader,
    StreamWriter, ToBytestream,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum BgpNotificationPacket {
    MessageHeaderError(BgpMessageHeaderError) = 1,
    OpenMessageError(BgpOpenMessageError) = 2,
    UpdateMessageError(BgpUpdateMessageError) = 3,
    HoldTimerExpires() = 4,
    FiniteStateMachineError() = 5,
    Cease() = 6,
}

impl ToBytestream for BgpNotificationPacket {
    type Error = Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        match self {
            Self::MessageHeaderError(err) => {
                1u8.write_to(stream, ByteOrder::BigEndian)?;
                err.to_bytestream(stream)
            }
            Self::OpenMessageError(err) => {
                2u8.write_to(stream, ByteOrder::BigEndian)?;
                err.to_bytestream(stream)
            }
            Self::UpdateMessageError(err) => {
                3u8.write_to(stream, ByteOrder::BigEndian)?;
                err.to_bytestream(stream)
            }
            Self::HoldTimerExpires() => {
                4u8.write_to(stream, ByteOrder::BigEndian)?;
                0u8.write_to(stream, ByteOrder::BigEndian)
            }
            Self::FiniteStateMachineError() => {
                5u8.write_to(stream, ByteOrder::BigEndian)?;
                0u8.write_to(stream, ByteOrder::BigEndian)
            }
            Self::Cease() => {
                6u8.write_to(stream, ByteOrder::BigEndian)?;
                0u8.write_to(stream, ByteOrder::BigEndian)
            }
        }
    }
}

impl FromBytestream for BgpNotificationPacket {
    type Error = Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let code = u8::read_from(stream, ByteOrder::BigEndian)?;
        match code {
            1 => Ok(BgpNotificationPacket::MessageHeaderError(
                BgpMessageHeaderError::from_bytestream(stream)?,
            )),
            2 => Ok(BgpNotificationPacket::OpenMessageError(
                BgpOpenMessageError::from_bytestream(stream)?,
            )),
            3 => Ok(BgpNotificationPacket::UpdateMessageError(
                BgpUpdateMessageError::from_bytestream(stream)?,
            )),
            4 => Ok(BgpNotificationPacket::HoldTimerExpires()),
            5 => Ok(BgpNotificationPacket::FiniteStateMachineError()),
            6 => Ok(BgpNotificationPacket::Cease()),
            _ => Err(Error::new(ErrorKind::InvalidData, "unknown error code")),
        }
    }
}

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BgpMessageHeaderError {
        type Repr = u8 where ByteOrder::BigEndian;
        ConnectionNotSynchronized = 1,
        BadMessageLength = 2,
        BadMessageTyp = 3,
    }
}

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BgpOpenMessageError {
        type Repr = u8 where ByteOrder::BigEndian;
        UnsupportedVersionNumber = 1,
        BadPeerAs = 2,
        BadBgpIdentifer = 3,
        UnsupportedOptionalParameter = 4,
        // depc = 5
        UnacceptableHoldTime = 6,
    }
}

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BgpUpdateMessageError {
        type Repr = u8 where ByteOrder::BigEndian;

        MalformedAttributeList = 1,
        UnrecognizedWellKnownAttribute = 2,
        MissingWellKnownAttribute = 3,
        AttributeFlagsError = 4,
        AttributeLengthError = 5,
        InvalidOriginAttribute = 6,
        InvalidNextHopAttribute = 8,
        OptionalAttributeError = 9,
        InvalidNetworkField = 10,
        MalformedAsPath = 11,
    }
}

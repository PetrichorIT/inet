use std::io::{Error, ErrorKind};

use bytes_io::{BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};
use macros::repr_enum;

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

const KIND_MESSAGE_HEADER_ERROR: u8 = 1;
const KIND_OPEN_MESSAGE_ERROR: u8 = 2;
const KIND_UPDATE_MESSAGE_ERROR: u8 = 3;
const KIND_HOLD_TIMER_EXPIRES: u8 = 4;
const KIND_FINITE_STATE_MACHINE_ERROR: u8 = 5;
const KIND_CEASE: u8 = 6;

impl ToBytes for BgpNotificationPacket {
    type Error = Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
        match self {
            Self::MessageHeaderError(err) => {
                stream.write_u8(KIND_MESSAGE_HEADER_ERROR)?;
                stream.write_u8(err.to_raw_repr())
            }
            Self::OpenMessageError(err) => {
                stream.write_u8(KIND_OPEN_MESSAGE_ERROR)?;
                stream.write_u8(err.to_raw_repr())
            }
            Self::UpdateMessageError(err) => {
                stream.write_u8(KIND_UPDATE_MESSAGE_ERROR)?;
                stream.write_u8(err.to_raw_repr())
            }
            Self::HoldTimerExpires() => {
                stream.write_u8(KIND_HOLD_TIMER_EXPIRES)?;
                stream.write_u8(0)
            }
            Self::FiniteStateMachineError() => {
                stream.write_u8(KIND_FINITE_STATE_MACHINE_ERROR)?;
                stream.write_u8(0)
            }
            Self::Cease() => {
                stream.write_u8(KIND_CEASE)?;
                stream.write_u8(0)
            }
        }
    }
}

impl FromBytes for BgpNotificationPacket {
    type Error = Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let code = stream.read_u8()?;
        let subcode = stream.read_u8()?;
        match code {
            KIND_MESSAGE_HEADER_ERROR => Ok(BgpNotificationPacket::MessageHeaderError(
                BgpMessageHeaderError::from_raw_repr(subcode)?,
            )),
            KIND_OPEN_MESSAGE_ERROR => Ok(BgpNotificationPacket::OpenMessageError(
                BgpOpenMessageError::from_raw_repr(subcode)?,
            )),
            KIND_UPDATE_MESSAGE_ERROR => Ok(BgpNotificationPacket::UpdateMessageError(
                BgpUpdateMessageError::from_raw_repr(subcode)?,
            )),
            KIND_HOLD_TIMER_EXPIRES => Ok(BgpNotificationPacket::HoldTimerExpires()),
            KIND_FINITE_STATE_MACHINE_ERROR => Ok(BgpNotificationPacket::FiniteStateMachineError()),
            KIND_CEASE => Ok(BgpNotificationPacket::Cease()),
            _ => Err(Error::new(ErrorKind::InvalidData, "unknown error code")),
        }
    }
}

repr_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BgpMessageHeaderError {
        type Repr = u8 where ByteOrder::BigEndian;
        ConnectionNotSynchronized = 1,
        BadMessageLength = 2,
        BadMessageTyp = 3,
    }
}

repr_enum! {
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

repr_enum! {
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

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;

    use super::*;

    #[test]
    fn e2e_encoding() {
        assert_encoding_e2e(&[
            BgpNotificationPacket::UpdateMessageError(
                BgpUpdateMessageError::InvalidNextHopAttribute,
            ),
            BgpNotificationPacket::UpdateMessageError(
                BgpUpdateMessageError::MalformedAttributeList,
            ),
            BgpNotificationPacket::OpenMessageError(BgpOpenMessageError::BadPeerAs),
            BgpNotificationPacket::OpenMessageError(
                BgpOpenMessageError::UnsupportedOptionalParameter,
            ),
            BgpNotificationPacket::MessageHeaderError(BgpMessageHeaderError::BadMessageLength),
            BgpNotificationPacket::MessageHeaderError(
                BgpMessageHeaderError::ConnectionNotSynchronized,
            ),
            BgpNotificationPacket::HoldTimerExpires(),
            BgpNotificationPacket::FiniteStateMachineError(),
            BgpNotificationPacket::Cease(),
        ]);
    }
}

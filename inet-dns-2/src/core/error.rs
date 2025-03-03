use std::{error::Error as StdError, fmt::Display, io};

use bytepack::raw_enum;

#[derive(Debug)]
pub struct Error {
    response_code: ResponseCode,
    error: Box<dyn std::error::Error + Send + Sync>,
}

impl Error {
    pub fn response_code(&self) -> ResponseCode {
        self.response_code
    }

    pub fn new<E>(response_code: ResponseCode, error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            response_code,
            error: error.into(),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.response_code, self.error)
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.response_code == other.response_code
    }
}

impl Eq for Error {}

impl StdError for Error {}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, value)
    }
}

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum ResponseCode {
        type Repr = u8 where BE;

        NoError = 0,
        FormError = 1,
        ServFail = 2,
        NxDomain = 3,
        NotImpl = 4,
        Refused = 5,
        YXDomain = 6,
        YXRRSet = 7,
        NXRRSet = 8,
        NotAuth = 9,
        NotZone = 10,
        DSOTypeNotImplemented = 11,
        BadOPTVersionOrSignature = 16,
        BadKey = 17,
        BadTime = 18,
        BadMode = 19,
        BadName = 20,
        BadAlgo = 21,
        BadTrunc = 22,
        BadCookie = 23,
    }
}

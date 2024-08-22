use std::fmt::Display;

use bytepack::raw_enum;

#[derive(Debug)]
pub struct DnsError {
    response_code: DnsResponseCode,
    error: Box<dyn std::error::Error>,
}

impl DnsError {
    pub fn response_code(&self) -> DnsResponseCode {
        self.response_code
    }

    pub fn new<E>(response_code: DnsResponseCode, error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error>>,
    {
        Self {
            response_code,
            error: error.into(),
        }
    }
}

impl Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.response_code, self.error)
    }
}

impl std::error::Error for DnsError {}

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DnsResponseCode {
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

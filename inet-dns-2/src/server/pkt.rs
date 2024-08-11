use bytepack::{
    raw_enum, BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream,
    WriteBytesExt, BE,
};

use crate::core::{
    DnsQuestion, DnsResourceRecord, DnsString, QueryResponse, QuestionClass, QuestionTyp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct DnsMessage {
    pub transaction: u16,
    // # Headers
    pub qr: bool,
    pub opcode: DnsOpCode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: DnsResponseCode,
    // [u16; 4] lengths of all 4 question sections.
    // # Questions + Anwsers
    pub response: QueryResponse,
}

impl DnsMessage {
    pub fn question_a(transaction: u16, name: impl Into<DnsString>) -> Self {
        Self {
            transaction,
            qr: false,
            opcode: DnsOpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,

            rcode: DnsResponseCode::NoError,
            response: QueryResponse {
                questions: vec![DnsQuestion {
                    qname: name.into(),
                    qtyp: QuestionTyp::A,
                    qclass: QuestionClass::IN,
                }],
                ..Default::default()
            },
        }
    }

    pub fn question_aaaa(transaction: u16, name: impl Into<DnsString>) -> Self {
        Self {
            transaction,
            qr: false,
            opcode: DnsOpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,

            rcode: DnsResponseCode::NoError,

            response: QueryResponse {
                questions: vec![DnsQuestion {
                    qname: name.into(),
                    qtyp: QuestionTyp::AAAA,
                    qclass: QuestionClass::IN,
                }],
                ..Default::default()
            },
        }
    }

    pub fn response(&self) -> impl Iterator<Item = &DnsResourceRecord> {
        self.response
            .anwsers
            .iter()
            .chain(self.response.auths.iter())
            .chain(self.response.additional.iter())
    }

    pub fn into_records(self) -> impl Iterator<Item = DnsResourceRecord> {
        self.response
            .anwsers
            .into_iter()
            .chain(self.response.auths.into_iter())
            .chain(self.response.additional.into_iter())
    }
}

impl ToBytestream for DnsMessage {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.transaction)?;
        let mut b0 = self.opcode.to_raw_repr() << 3;
        if self.qr {
            b0 |= 0b1000_0000;
        }
        if self.aa {
            b0 |= 0b0000_0100;
        }
        if self.tc {
            b0 |= 0b0000_0010;
        }
        if self.rd {
            b0 |= 0b0000_0001;
        }
        stream.write_u8(b0)?;

        let mut b1 = self.rcode.to_raw_repr();
        if self.ra {
            b1 |= 0b1000_0000;
        }
        stream.write_u8(b1)?;

        stream.write_u16::<BE>(self.response.questions.len() as u16)?;
        stream.write_u16::<BE>(self.response.anwsers.len() as u16)?;
        stream.write_u16::<BE>(self.response.auths.len() as u16)?;
        stream.write_u16::<BE>(self.response.additional.len() as u16)?;

        for q in &self.response.questions {
            q.to_bytestream(stream)?;
        }
        for a in &self.response.anwsers {
            a.to_bytestream(stream)?;
        }
        for a in &self.response.auths {
            a.to_bytestream(stream)?;
        }
        for a in &self.response.additional {
            a.to_bytestream(stream)?;
        }

        Ok(())
    }
}

impl FromBytestream for DnsMessage {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let transaction = stream.read_u16::<BE>()?;
        let b0 = stream.read_u8()?;
        let b1 = stream.read_u8()?;

        let qr = (0b1000_0000 & b0) != 0;
        let aa = (0b0000_0100 & b0) != 0;
        let tc = (0b0000_0010 & b0) != 0;
        let rd = (0b0000_0001 & b0) != 0;
        let opcode = DnsOpCode::from_raw_repr((b0 >> 3) & 0b1111).unwrap();

        let ra = (0b1000_0000 & b1) != 0;
        let rcode = DnsResponseCode::from_raw_repr(b1 & 0b1111u8).unwrap();

        let questions_len = stream.read_u16::<BE>()?;
        let anwsers_len = stream.read_u16::<BE>()?;
        let auth_len = stream.read_u16::<BE>()?;
        let additional_len = stream.read_u16::<BE>()?;

        let mut questions = Vec::new();

        for _ in 0..questions_len {
            let v = DnsQuestion::from_bytestream(stream)?;
            questions.push(v);
        }

        // println!("> done q");

        let mut anwsers = Vec::new();
        for _ in 0..anwsers_len {
            let v = DnsResourceRecord::from_bytestream(stream)?;
            anwsers.push(v);
        }

        // println!("> done a");

        let mut auths = Vec::new();
        for _ in 0..auth_len {
            let v = DnsResourceRecord::from_bytestream(stream)?;
            auths.push(v);
        }

        let mut additional = Vec::new();
        for _ in 0..additional_len {
            let v = DnsResourceRecord::from_bytestream(stream)?;
            additional.push(v);
        }

        Ok(DnsMessage {
            transaction,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            rcode,
            response: QueryResponse {
                questions,
                anwsers,
                auths,
                additional,
            },
        })
    }
}

// # DNSOpCode

raw_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DnsOpCode {
        type Repr = u8 where BE;

        Query = 0,
        IQuery = 1,
        Status = 2,
    }
}

// # DNSReponseCode

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

use super::{DNSClass, DNSResourceRecord, DNSString, DNSType};
use bytepack::{
    BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream, WriteBytesExt,
    BE,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::struct_excessive_bools)]
pub struct DNSMessage {
    pub transaction: u16,
    // # Headers
    pub qr: bool,
    pub opcode: DNSOpCode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: DNSResponseCode,
    // [u16; 4] lengths of all 4 question sections.
    // # Questions
    pub questions: Vec<DNSQuestion>,
    // # Anwsers
    pub anwsers: Vec<DNSResourceRecord>,
    // # Authority
    pub auths: Vec<DNSResourceRecord>,
    // # Additional
    pub additional: Vec<DNSResourceRecord>,
}

impl DNSMessage {
    pub fn question_a(transaction: u16, name: impl Into<DNSString>) -> Self {
        Self {
            transaction,
            qr: false,
            opcode: DNSOpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,

            rcode: DNSResponseCode::NoError,
            questions: vec![DNSQuestion {
                qname: name.into(),
                qtyp: DNSType::A,
                qclass: DNSClass::Internet,
            }],
            anwsers: Vec::new(),
            auths: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn question_aaaa(transaction: u16, name: impl Into<DNSString>) -> Self {
        Self {
            transaction,
            qr: false,
            opcode: DNSOpCode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,

            rcode: DNSResponseCode::NoError,
            questions: vec![DNSQuestion {
                qname: name.into(),
                qtyp: DNSType::AAAA,
                qclass: DNSClass::Internet,
            }],
            anwsers: Vec::new(),
            auths: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn response(&self) -> impl Iterator<Item = &DNSResourceRecord> {
        self.anwsers
            .iter()
            .chain(self.auths.iter())
            .chain(self.additional.iter())
    }

    pub fn into_records(self) -> impl Iterator<Item = DNSResourceRecord> {
        self.anwsers
            .into_iter()
            .chain(self.auths.into_iter())
            .chain(self.additional.into_iter())
    }
}

impl ToBytestream for DNSMessage {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        stream.write_u16::<BE>(self.transaction)?;
        let mut b0 = self.opcode.to_raw() << 3;
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

        let mut b1 = self.rcode.to_raw();
        if self.ra {
            b1 |= 0b1000_0000;
        }
        stream.write_u8(b1)?;

        stream.write_u16::<BE>(self.questions.len() as u16)?;
        stream.write_u16::<BE>(self.anwsers.len() as u16)?;
        stream.write_u16::<BE>(self.auths.len() as u16)?;
        stream.write_u16::<BE>(self.additional.len() as u16)?;

        for q in &self.questions {
            q.to_bytestream(stream)?;
        }
        for a in &self.anwsers {
            a.to_bytestream(stream)?;
        }
        for a in &self.auths {
            a.to_bytestream(stream)?;
        }
        for a in &self.additional {
            a.to_bytestream(stream)?;
        }

        Ok(())
    }
}

impl FromBytestream for DNSMessage {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let transaction = stream.read_u16::<BE>()?;
        let b0 = stream.read_u8()?;
        let b1 = stream.read_u8()?;

        let qr = (0b1000_0000 & b0) != 0;
        let aa = (0b0000_0100 & b0) != 0;
        let tc = (0b0000_0010 & b0) != 0;
        let rd = (0b0000_0001 & b0) != 0;
        let opcode = DNSOpCode::from_raw((b0 >> 3) & 0b1111).unwrap();

        let ra = (0b1000_0000 & b1) != 0;
        let rcode = DNSResponseCode::from_raw(b1 & 0b1111u8).unwrap();

        let questions_len = stream.read_u16::<BE>()?;
        let anwsers_len = stream.read_u16::<BE>()?;
        let auth_len = stream.read_u16::<BE>()?;
        let additional_len = stream.read_u16::<BE>()?;

        let mut questions = Vec::new();

        for _ in 0..questions_len {
            let v = DNSQuestion::from_bytestream(stream)?;
            questions.push(v);
        }

        // println!("> done q");

        let mut anwsers = Vec::new();
        for _ in 0..anwsers_len {
            let v = DNSResourceRecord::from_bytestream(stream)?;
            anwsers.push(v);
        }

        // println!("> done a");

        let mut auths = Vec::new();
        for _ in 0..auth_len {
            let v = DNSResourceRecord::from_bytestream(stream)?;
            auths.push(v);
        }

        let mut additional = Vec::new();
        for _ in 0..additional_len {
            let v = DNSResourceRecord::from_bytestream(stream)?;
            additional.push(v);
        }

        Ok(DNSMessage {
            transaction,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            rcode,
            questions,
            anwsers,
            auths,
            additional,
        })
    }
}

// # DNSOpCode

primitve_enum_repr! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DNSOpCode {
        type Repr = u8;

        Query = 0,
        IQuery = 1,
        Status = 2,
    };
}

// # DNSReponseCode

primitve_enum_repr! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum DNSResponseCode {
        type Repr = u8;

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
    };
}

// # DNS Q

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSQuestion {
    pub qname: DNSString,
    pub qtyp: DNSType,
    pub qclass: DNSClass,
}

impl ToBytestream for DNSQuestion {
    type Error = std::io::Error;
    fn to_bytestream(&self, stream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        self.qname.to_bytestream(stream)?;
        stream.write_u16::<BE>(self.qtyp.to_raw())?;
        stream.write_u16::<BE>(self.qclass.to_raw())?;
        Ok(())
    }
}

impl FromBytestream for DNSQuestion {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let qname = DNSString::from_bytestream(stream)?;

        let qtyp = DNSType::from_raw(stream.read_u16::<BE>()?).unwrap();
        let qclass = DNSClass::from_raw(stream.read_u16::<BE>()?).unwrap();

        Ok(DNSQuestion {
            qname,
            qtyp,
            qclass,
        })
    }
}

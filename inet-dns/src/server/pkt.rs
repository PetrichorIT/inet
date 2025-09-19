use bytes_io::{BE, BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};
use macros::repr_enum;

use crate::core::{
    DnsResourceRecord, DnsString, OptResourceRecord, QueryResponse, Question, QuestionClass,
    QuestionTyp, ResourceRecordTyp, ResponseCode,
};

use super::{
    NameserverQuery,
    transaction::{FinishedTransaction, TransactionResult},
};

/// A DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct DnsMessage {
    /// The transaction ID that uniquely identifies this message per client-server pair.
    pub transaction: u16,
    /// A flag indicating whether this message is a query (false) or a response (true).
    pub qr: bool,
    /// The opcode of the message.
    pub opcode: OpCode,
    /// The authoritative answer flag.
    pub aa: bool,
    /// The truncation flag.
    pub tc: bool,
    /// The recursion desired flag.
    pub rd: bool,
    /// The recursion available flag.
    pub ra: bool,
    /// The response code.
    pub rcode: ResponseCode,
    /// The data section of the message, containing resource records.
    pub response: QueryResponse,
}

impl DnsMessage {
    pub fn question_a(transaction: u16, qname: DnsString) -> Self {
        Self::query(
            transaction,
            Question {
                qname,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            },
        )
    }

    pub fn question_aaaa(transaction: u16, qname: DnsString) -> Self {
        Self::query(
            transaction,
            Question {
                qname,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::AAAA,
            },
        )
    }

    pub fn query(transaction: u16, question: Question) -> Self {
        Self {
            transaction,
            qr: false,
            opcode: OpCode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            rcode: ResponseCode::NoError,
            response: QueryResponse {
                questions: vec![question],
                ..Default::default()
            },
        }
    }

    pub fn response_from_transaction(tx: FinishedTransaction) -> Self {
        match tx.result {
            TransactionResult::Success(response) => Self {
                transaction: tx.query.transaction,
                qr: true,
                opcode: OpCode::Query,
                aa: tx.aa,
                tc: false,
                rd: false,
                ra: tx.ra,
                rcode: ResponseCode::NoError,
                response,
            },
            TransactionResult::Failure(error) => Self {
                transaction: tx.query.transaction,
                qr: true,
                opcode: OpCode::Query,
                aa: tx.aa,
                tc: false,
                rd: false,
                ra: tx.ra,
                rcode: error.response_code(),
                response: QueryResponse {
                    questions: vec![tx.query.question.clone()],
                    ..Default::default()
                },
            },
        }
    }

    pub fn request_from_ns_query(ns_query: NameserverQuery) -> Self {
        Self {
            transaction: ns_query.transaction,
            qr: false,
            opcode: OpCode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            rcode: ResponseCode::NoError,
            response: QueryResponse {
                questions: vec![ns_query.query.question.clone()],
                ..Default::default()
            },
        }
    }

    pub fn with_edns(mut self, edns: bool) -> Self {
        if edns {
            self.response.additional.push(
                OptResourceRecord {
                    name: DnsString::empty(),
                    udp_payload_size: 1200,
                    rcode: 0,
                    version: true,
                    options: Vec::new(),
                }
                .into(),
            );
        }
        self
    }

    pub fn edns(&self) -> Option<&OptResourceRecord> {
        self.response.additional.iter().find_map(|v| {
            (v.typ() == ResourceRecordTyp::OPT)
                .then(|| v.as_any().downcast_ref::<OptResourceRecord>())
                .flatten()
        })
    }

    pub fn response(&self) -> impl Iterator<Item = &DnsResourceRecord> {
        self.response
            .anwsers
            .iter()
            .chain(self.response.auths.iter())
            .chain(
                self.response
                    .additional
                    .iter()
                    .filter(|rr| rr.typ() != ResourceRecordTyp::OPT),
            )
    }

    pub fn into_records(self) -> impl Iterator<Item = DnsResourceRecord> {
        self.response
            .anwsers
            .into_iter()
            .chain(self.response.auths)
            .chain(self.response.additional)
    }

    // TODO: this is ineffecient as fk
    pub fn truncate(&mut self) {
        self.tc = true;

        if self.response.additional.pop().is_some() {
            return;
        }
        if self.response.auths.pop().is_some() {
            return;
        }
        if self.response.anwsers.pop().is_some() {
            return;
        }

        unreachable!("this point should never be reached")
    }
}

impl ToBytes for DnsMessage {
    type Error = std::io::Error;
    fn to_bytes(&self, stream: &mut BytesWriter) -> Result<(), Self::Error> {
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
            q.to_bytes(stream)?;
        }
        for a in &self.response.anwsers {
            a.to_bytes(stream)?;
        }
        for a in &self.response.auths {
            a.to_bytes(stream)?;
        }
        for a in &self.response.additional {
            a.to_bytes(stream)?;
        }

        Ok(())
    }
}

impl FromBytes for DnsMessage {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let transaction = stream.read_u16::<BE>()?;
        let b0 = stream.read_u8()?;
        let b1 = stream.read_u8()?;

        let qr = (0b1000_0000 & b0) != 0;
        let aa = (0b0000_0100 & b0) != 0;
        let tc = (0b0000_0010 & b0) != 0;
        let rd = (0b0000_0001 & b0) != 0;
        let opcode = OpCode::from_raw_repr((b0 >> 3) & 0b1111).unwrap();

        let ra = (0b1000_0000 & b1) != 0;
        let rcode = ResponseCode::from_raw_repr(b1 & 0b1111u8).unwrap();

        let questions_len = stream.read_u16::<BE>()?;
        let anwsers_len = stream.read_u16::<BE>()?;
        let auth_len = stream.read_u16::<BE>()?;
        let additional_len = stream.read_u16::<BE>()?;

        let mut questions = Vec::new();

        for _ in 0..questions_len {
            let v = Question::from_bytes(stream)?;
            questions.push(v);
        }

        // println!("> done q");

        let mut anwsers = Vec::new();
        for _ in 0..anwsers_len {
            let v = DnsResourceRecord::from_bytes(stream)?;
            anwsers.push(v);
        }

        // println!("> done a");

        let mut auths = Vec::new();
        for _ in 0..auth_len {
            let v = DnsResourceRecord::from_bytes(stream)?;
            auths.push(v);
        }

        let mut additional = Vec::new();
        for _ in 0..additional_len {
            let v = DnsResourceRecord::from_bytes(stream)?;
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

repr_enum! {
    /// The operation code of a DNS message.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum OpCode {
        type Repr = u8 where BE;

        Query = 0,
        IQuery = 1,
        Status = 2,
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, sync::Arc};

    use bytes_io::assert_encoding_e2e;

    use crate::{
        core::{AResourceRecord, ResourceRecordClass},
        server::{SourceQuery, TransportMedium},
    };

    use super::*;

    #[test]
    fn e2e_encoding_query() -> io::Result<()> {
        assert_encoding_e2e(&[
            DnsMessage::question_a(1323, "www.example.com.".parse()?),
            DnsMessage::question_aaaa(3131, "this.is.ipv6.de.".parse()?),
            DnsMessage::question_a(0, "a.b.c.".parse()?).with_edns(true),
            DnsMessage::query(
                31,
                Question {
                    qname: "example.com.".parse()?,
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::PTR,
                },
            ),
            DnsMessage::query(
                3331,
                Question {
                    qname: "example.com.".parse()?,
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::NS,
                },
            ),
        ]);
        Ok(())
    }

    #[test]
    fn e2e_encoding_response() -> io::Result<()> {
        assert_encoding_e2e(
            &[DnsMessage::response_from_transaction(FinishedTransaction {
                query: Arc::new(SourceQuery {
                    medium: TransportMedium::Udp,
                    edns: None,
                    addr: "3.13.1.3:313".parse().unwrap(),
                    transaction: 3,
                    question: Question {
                        qname: "example.com.".parse()?,
                        qclass: QuestionClass::IN,
                        qtyp: QuestionTyp::A,
                    },
                }),
                aa: true,
                ra: false,
                result: TransactionResult::Success(QueryResponse {
                    questions: vec![Question {
                        qname: "example.com.".parse()?,
                        qclass: QuestionClass::IN,
                        qtyp: QuestionTyp::A,
                    }],
                    anwsers: vec![
                        AResourceRecord {
                            name: "example.com.".parse()?,
                            ttl: 3600,
                            class: ResourceRecordClass::IN,
                            addr: Ipv4Addr::new(1, 2, 3, 4),
                        }
                        .into(),
                    ],
                    ..Default::default()
                }),
            })],
        );
        Ok(())
    }
}

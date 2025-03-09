use std::{net::Ipv4Addr, str::FromStr};

use des::{
    net::{AsyncFn, Sim},
    runtime::Builder,
    time::sleep,
};
use serial_test::serial;

use crate::{
    core::{Error, QueryResponse, ResourceRecordClass},
    server::OpCode,
};

use super::*;

const ZONEFILE_ORG: &str = include_str!("../../examples/org.zone");

#[test]
#[serial]
fn referral_anwser_finishes_transaction() {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            let zone = Zonefile::from_str(ZONEFILE_ORG)?;
            let mut server = RecursiveNameserver::new(zone)?;

            let addr = "2.2.2.2:2".parse().unwrap();
            server.incoming(
                TransportMedium::Udp,
                addr,
                DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?),
            );

            let question = Question {
                qname: "alice.example.org.".parse()?,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            };
            let query = Arc::new(SourceQuery {
                medium: TransportMedium::Udp,
                edns: None,
                question: question.clone(),
                transaction: 1,
                addr,
            });

            let nsaddr = Ipv4Addr::new(192, 168, 2, 30).into();

            assert_eq!(server.anwsers(), []);
            assert_eq!(
                server.ns_queries(),
                [NameserverQuery {
                    nameserver_ip: nsaddr,
                    transaction: 1,
                    preferred: None,
                    query: query.clone()
                }]
            );

            let resp = QueryResponse {
                questions: vec![question.clone()],
                anwsers: vec![AResourceRecord {
                    name: "alice.example.org.".parse()?,
                    ttl: 7000,
                    class: ResourceRecordClass::IN,
                    addr: Ipv4Addr::new(1, 2, 3, 4),
                }
                .into()],
                ..Default::default()
            };
            server.incoming(
                TransportMedium::Udp,
                SocketAddr::new(nsaddr, 43),
                DnsMessage {
                    transaction: 1,
                    qr: true,
                    ra: false,
                    rd: false,
                    aa: false,
                    tc: false,
                    opcode: OpCode::Query,
                    rcode: ResponseCode::NoError,
                    response: resp.clone(),
                },
            );

            assert_eq!(
                server.anwsers(),
                [FinishedTransaction {
                    query,
                    ra: true,
                    aa: false,
                    result: TransactionResult::Success(resp)
                }]
            );
            assert_eq!(server.ns_queries(), []);

            Ok(())
        }),
    );
    let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
}

#[test]
#[serial]
fn referred_error_will_be_propagated() {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            let zone = Zonefile::from_str(ZONEFILE_ORG)?;
            let mut server = RecursiveNameserver::new(zone)?;

            let addr = "2.2.2.2:2".parse().unwrap();
            server.incoming(
                TransportMedium::Udp,
                addr,
                DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?),
            );

            let question = Question {
                qname: "alice.example.org.".parse()?,
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::A,
            };
            let query = Arc::new(SourceQuery {
                medium: TransportMedium::Udp,
                edns: None,
                question: question.clone(),
                transaction: 1,
                addr,
            });

            let nsaddr = Ipv4Addr::new(192, 168, 2, 30).into();

            assert_eq!(server.anwsers(), []);
            assert_eq!(
                server.ns_queries(),
                [NameserverQuery {
                    nameserver_ip: nsaddr,
                    transaction: 1,
                    preferred: None,
                    query: query.clone()
                }]
            );

            server.incoming(
                TransportMedium::Udp,
                SocketAddr::new(nsaddr, 43),
                DnsMessage::response_from_transaction(FinishedTransaction {
                    query: Arc::new(SourceQuery {
                        medium: TransportMedium::Udp,
                        edns: None,
                        question: question.clone(),
                        transaction: 1,
                        addr: SocketAddr::new(nsaddr, 43),
                    }),
                    ra: true,
                    aa: false,
                    result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, "")),
                }),
            );

            assert_eq!(
                server.anwsers(),
                [FinishedTransaction {
                    query: Arc::new(SourceQuery {
                        medium: TransportMedium::Udp,
                        edns: None,
                        question: question.clone(),
                        transaction: 1,
                        addr,
                    }),
                    ra: true,
                    aa: false,
                    result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, "")),
                }]
            );
            assert_eq!(server.ns_queries(), []);

            Ok(())
        }),
    );
    let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
}

#[test]
#[serial]
fn timeout_will_end_in_error() {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            let zone = Zonefile::from_str(ZONEFILE_ORG)?;
            let mut server = RecursiveNameserver::new(zone)?;

            let addr = "2.2.2.2:2".parse().unwrap();
            server.incoming(
                TransportMedium::Udp,
                addr,
                DnsMessage::question_a(1, "alice.example.org.".parse::<DnsString>()?),
            );

            assert_eq!(server.anwsers().len(), 0);
            assert_eq!(server.ns_queries().len(), 1);

            sleep(Duration::from_secs(2)).await;

            server.tick();
            assert_eq!(
                server.anwsers(),
                [FinishedTransaction {
                    query: Arc::new(SourceQuery {
                        medium: TransportMedium::Udp,
                        edns: None,
                        question: Question {
                            qname: "alice.example.org.".parse()?,
                            qclass: QuestionClass::IN,
                            qtyp: QuestionTyp::A
                        },
                        transaction: 1,
                        addr,
                    }),
                    ra: true,
                    aa: false,
                    result: TransactionResult::Failure(Error::new(ResponseCode::NxDomain, ""))
                }]
            );

            Ok(())
        }),
    );
    let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
}

const ZONEFILE_EXAMPLE_ORG: &str = include_str!("../../examples/example.org.zone");

#[test]
#[serial]
fn timeout_will_retransmit_to_other_ns() {
    let mut sim = Sim::new(()).with_stack(inet::init);
    sim.node(
        "alice",
        AsyncFn::io(|_| async move {
            let zone = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;
            let mut server = RecursiveNameserver::new(zone)?;

            let addr = "2.2.2.2:2".parse().unwrap();
            server.incoming(
                TransportMedium::Udp,
                addr,
                DnsMessage::question_a(1, "www.subdomain.example.org.".parse::<DnsString>()?),
            );

            assert_eq!(server.anwsers().len(), 0);
            assert_eq!(server.ns_queries().len(), 1);

            sleep(Duration::from_secs(2)).await;
            server.tick();

            assert_eq!(server.anwsers().len(), 0);
            assert_eq!(server.ns_queries().len(), 1);

            sleep(Duration::from_secs(2)).await;
            server.tick();

            assert_eq!(server.anwsers().len(), 1);
            assert_eq!(server.ns_queries().len(), 0);

            Ok(())
        }),
    );
    let _ = Builder::seeded(123).max_time(100.0.into()).build(sim).run();
}

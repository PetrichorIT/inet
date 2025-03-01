// use std::{
//     error::Error,
//     net::{IpAddr, Ipv4Addr, SocketAddr},
//     str::FromStr,
// };

// use des::runtime::Builder;
// use inet_dns_2::{
//     core::{DnsQuestion, DnsString, DnsZoneResolver, QuestionClass, QuestionTyp, Zonefile},
//     server::{DnsIterativeNameserver, DnsMessage, DnsRecursiveNameserver},
// };

// const ZONEFILE_ROOT: &str = include_str!("data/root.zone");
// const ZONEFILE_ORG: &str = include_str!("data/org.zone");
// const ZONEFILE_EXAMPLE_ORG: &str = include_str!("data/example.org.zone");

// #[test]
// fn main() {
//     let _ = Builder::new()
//         .max_itr(1000)
//         .build(|| {
//             let root = DnsIterativeNameserver::new(vec![DnsZoneResolver::new(
//                 Zonefile::from_str(ZONEFILE_ROOT)?,
//             )?]);

//             let org = DnsIterativeNameserver::new(vec![DnsZoneResolver::new(Zonefile::from_str(
//                 ZONEFILE_ORG,
//             )?)?]);

//             let example_org = DnsIterativeNameserver::new(vec![DnsZoneResolver::new(
//                 Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?,
//             )?]);

//             let mut resolver = DnsRecursiveNameserver::new(Zonefile::local())?.with_roots(vec![(
//                 IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10)),
//                 String::new(),
//             )]);

//             resolver.handle_query(
//                 "192.168.0.2:5000".parse()?,
//                 42,
//                 DnsQuestion {
//                     qname: DnsString::from_str("www.example.org.")?,
//                     qtyp: QuestionTyp::A,
//                     qclass: QuestionClass::IN,
//                 },
//             );

//             loop {
//                 // Ask questions
//                 let responses = resolver
//                     .queries
//                     .drain(..)
//                     .map(|query| {
//                         println!(">> Request {} to {}", query.question, query.nameserver_ip);
//                         let s = match query.nameserver_ip.to_string().as_str() {
//                             "192.168.2.10" => &root,
//                             "192.168.2.20" => &org,
//                             "192.168.2.30" => &example_org,
//                             _ => unreachable!(),
//                         };

//                         let resp = s.handle(&query.question).unwrap();
//                         (query.clone(), resp)
//                     })
//                     .collect::<Vec<_>>();

//                 for (query, response) in responses {
//                     println!(
//                         "<< Response from {} regardning {}: {response}",
//                         query.nameserver_ip, query.question
//                     );
//                     resolver.handle_response(
//                         SocketAddr::new(query.nameserver_ip, 80),
//                         DnsMessage {
//                             transaction: query.transaction,
//                             qr: true,
//                             opcode: inet_dns_2::server::DnsOpCode::Query,
//                             aa: false,
//                             tc: false,
//                             rd: false,
//                             ra: false,
//                             rcode: inet_dns_2::core::DnsResponseCode::NoError,
//                             response,
//                         },
//                     );
//                 }

//                 if let Some(fin) = resolver.finished_transactions.first() {
//                     println!("{fin:?}");
//                     break;
//                 }
//             }

//             Ok::<_, Box<dyn Error>>(())
//         })
//         .run();
// }

use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use des::runtime::Builder;
use inet_dns_2::{
    core::{DnsQuestion, DnsString, DnsZoneResolver, QuestionClass, QuestionTyp, Zonefile},
    server::{DnsIterativeNameserver, DnsMessage, DnsRecursiveNameserver},
};

const ZONEFILE_ROOT: &str = r#"
. 7000 IN SOA a.root-servers.net. admin@a.net (7000 7000 7000 7000 700)

. 1800 IN NS a.root-server.net.
. 1800 IN NS b.root-servers.net.

org. 1800 IN NS ns0.nameservers.org.

ns0.nameservers.org. 1800 IN A 100.3.43.125
"#;

const ZONEFILE_ORG: &str = r#"
org. 7000 IN SOA ns0.namservers.org admin@org.org (7000 7000 7000 7000 7000)

org. 7000 IN NS ns0.nameservers.org.
example.org. 7000 IN NS ns1.example.org.
example.org. 7000 IN NS ns2.example.org.

ns1.example.org. 7000 IN A 100.78.43.100
ns1.example.org. 7000 IN AAAA be61:10fc:c150:264a:1129:27e:4a32:dbd9
ns2.example.org. 7000 IN A 100.78.43.200
"#;

const ZONEFILE_EXAMPLE_ORG: &str = r#"
example.org. 7000 IN SOA ns1.example.org. admin@example.org (7000 7000 7000 7000 7000)

example.org. 7000 IN NS ns1.example.org.
example.org. 7000 IN NS ns1.example.org.

ns1.example.org. 1800 IN A 100.78.43.100
ns2.example.org. 1800 IN A 100.78.43.200

www.example.org. 1800 IN A 9.9.9.9
www.example.org. 1800 IN AAAA 30ae:98dc:6ccf:595:1a0f:3680:d14e:a1f6
"#;

#[test]
fn main() {
    let _ = Builder::new()
        .build(|| {
            let root = DnsIterativeNameserver::new(vec![DnsZoneResolver::new(
                Zonefile::from_str(ZONEFILE_ROOT)?,
            )?]);

            let org = DnsIterativeNameserver::new(vec![DnsZoneResolver::new(Zonefile::from_str(
                ZONEFILE_ORG,
            )?)?]);

            let example_org = DnsIterativeNameserver::new(vec![DnsZoneResolver::new(
                Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?,
            )?]);

            let mut resolver = DnsRecursiveNameserver::new(Zonefile::local())?
                .with_roots(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);

            resolver.handle(
                "192.168.0.2:5000".parse()?,
                42,
                DnsQuestion {
                    qname: DnsString::from_str("www.example.org.")?,
                    qtyp: QuestionTyp::A,
                    qclass: QuestionClass::IN,
                },
            );

            loop {
                // Ask questions
                let responses = resolver
                    .queries
                    .drain(..)
                    .map(|query| {
                        println!(">> Request {} to {}", query.question, query.nameserver_ip);
                        let s = match query.nameserver_ip.to_string().as_str() {
                            "1.1.1.1" => &root,
                            "100.3.43.125" => &org,
                            "100.78.43.100" => &example_org,
                            "100.78.43.200" => &example_org,
                            _ => unreachable!(),
                        };

                        let resp = s.handle(&query.question).unwrap();
                        (query.clone(), resp)
                    })
                    .collect::<Vec<_>>();

                for (query, response) in responses {
                    println!(
                        "<< Response from {} regardning {}",
                        query.nameserver_ip, query.question
                    );
                    resolver.include(
                        SocketAddr::new(query.nameserver_ip, 80),
                        DnsMessage {
                            transaction: query.transaction,
                            qr: true,
                            opcode: inet_dns_2::server::DnsOpCode::Query,
                            aa: false,
                            tc: false,
                            rd: false,
                            ra: false,
                            rcode: inet_dns_2::core::DnsResponseCode::NoError,
                            response,
                        },
                    );
                }

                if let Some(fin) = resolver.finished_transactions.first() {
                    println!("{fin:?}");
                    break;
                }
            }

            Ok::<_, Box<dyn Error>>(())
        })
        .run();
}

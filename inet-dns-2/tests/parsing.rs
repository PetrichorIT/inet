use bytepack::*;
use inet_dns_2::core::{DnsQuestion, DnsResourceRecord, DnsString, DnsZoneResolver, Zonefile};
use std::str::FromStr;

const RAW2: &str = r#"
$ORIGIN example.com.
@   IN  SOA     VENERA      Action\.domains (
                                 20     ; SERIAL
                                 7200   ; REFRESH
                                 600    ; RETRY
                                 3600000; EXPIRE
                                 60)    ; MINIMUM

        NS      A.ISI.EDU.
        NS      VENERA
        NS      VAXA
        MX      10      VENERA
        MX      20      VAXA

A       A       26.3.0.103

VENERA  A       10.1.0.52
        A       128.9.0.32

VAXA    A       10.2.0.27
        A       128.9.0.33
"#;

#[test]
fn raw_zonefile() {
    let zf = Zonefile::from_str(RAW2).unwrap();
    for r in zf.records {
        let entry = DnsResourceRecord::try_from(r).expect("failed at ");

        let entry_reparsed = DnsResourceRecord::from_slice(&entry.to_vec().unwrap()).unwrap();
        assert_eq!(entry, entry_reparsed);
        println!("{entry_reparsed}");
    }
}

const ZONEFILE_ORG: &str = r#"
org. 7000 IN SOA ns0.namservers.org admin@org.org (7000 7000 7000 7000 7000)

org. 7000 IN NS ns0.nameservers.org.
example.org. 7000 IN NS ns1.example.org.
example.org. 7000 IN NS ns2.example.org.

ns1.example.org. 7000 IN A 100.78.43.100
ns1.example.org. 7000 IN AAAA be61:10fc:c150:264a:1129:27e:4a32:dbd9
ns2.example.org. 7000 IN A 100.78.43.200
"#;

#[test]
fn zonefile_with_referral() {
    let db = DnsZoneResolver::new(Zonefile::from_str(ZONEFILE_ORG).unwrap()).unwrap();
    let response = db
        .query(&DnsQuestion {
            qname: DnsString::from_str("www.example.org.").unwrap(),
            qtyp: inet_dns_2::core::QuestionTyp::A,
            qclass: inet_dns_2::core::QuestionClass::IN,
        })
        .unwrap();
    assert_eq!(response.auths.len(), 2, "was {:#?}", response);
    assert_eq!(response.additional.len(), 3, "was {:#?}", response);
}

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
fn zonefile_with_anweser() {
    let db = DnsZoneResolver::new(Zonefile::from_str(ZONEFILE_EXAMPLE_ORG).unwrap()).unwrap();
    let response = db
        .query(&DnsQuestion {
            qname: DnsString::from_str("www.example.org.").unwrap(),
            qtyp: inet_dns_2::core::QuestionTyp::A,
            qclass: inet_dns_2::core::QuestionClass::IN,
        })
        .unwrap();
    assert_eq!(response.anwsers.len(), 1, "was {:?}", response);

    let response = db
        .query(&DnsQuestion {
            qname: DnsString::from_str("www.example.org.").unwrap(),
            qtyp: inet_dns_2::core::QuestionTyp::AAAA,
            qclass: inet_dns_2::core::QuestionClass::IN,
        })
        .unwrap();
    assert_eq!(response.anwsers.len(), 1, "was {:?}", response);
}

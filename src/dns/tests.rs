use super::*;
use crate::{FromBytestream, IntoBytestream};

#[test]
fn dns_string_from_str() {
    let dns = DNSString2::new("www.example.com");
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "example");

    let dns = DNSString2::new("www.example.com.");
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "example");

    let dns = DNSString2::new("www.example.com".to_string());
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "example");

    let dns = DNSString2::new("www.example.com.".to_string());
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "example");

    let dns = DNSString2::new("mailserver.default.org.");
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "default");

    let dns = DNSString2::new("www.a.bzgtv");
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "a");

    let dns = DNSString2::new("a.a.uri.a.example.com.");
    assert_eq!(dns.labels(), 6);
    assert_eq!(dns.label(1), "a");

    let dns = DNSString2::new("a.a.uri.a.example.com:8000");
    assert_eq!(dns.labels(), 6);
    assert_eq!(dns.label(1), "a");

    let dns = DNSString2::new("a.a.uri.a.example.com:8000.");
    assert_eq!(dns.labels(), 6);
    assert_eq!(dns.label(1), "a");

    let dns = DNSString2::new("");
    assert_eq!(dns.labels(), 0);
}

#[test]
#[should_panic]
fn dns_string_from_non_ascii() {
    let _dns = DNSString2::new("www.😀.de");
}

#[test]
#[should_panic]
fn dns_string_from_empty_label() {
    let _dns = DNSString2::new("www..de");
}

#[test]
#[should_panic]
fn dns_string_from_non_network_forbidden_char() {
    let _dns = DNSString2::new("www.a#a.de");
}

#[test]
#[should_panic]
fn dns_string_from_non_network_missplaced_char() {
    let _dns = DNSString2::new("www.aa-.de");
}

#[test]
fn dns_string_parsing() {
    let inp = DNSString2::new("www.example.com");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString2::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString2::new("asg-erfurt.de");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString2::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString2::new("a.b.c.www.example.com:800");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString2::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString2::new("cdde.aaoa-adad.com.");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString2::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString2::new("www.out.out.out.com:80.");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString2::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString2::new("www.example.com");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString2::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);
}

#[test]
fn dns_string_suffix_checks() {
    let lhs = DNSString2::new("www.example.org");
    let rhs = DNSString2::new("n0.NIZ.org");
    assert_eq!(DNSString2::suffix_match_len(&lhs, &rhs), 1);

    let lhs = DNSString2::new("a.b.c.e.www.example.org");
    let rhs = DNSString2::new("n0.NIZ.org");
    assert_eq!(DNSString2::suffix_match_len(&lhs, &rhs), 1);

    let lhs = DNSString2::new("www.example.org");
    let rhs = DNSString2::new("www.example.oirg");
    assert_eq!(DNSString2::suffix_match_len(&lhs, &rhs), 0);

    let lhs = DNSString2::new("www.example.org");
    let rhs = DNSString2::new("n0.example.org");
    assert_eq!(DNSString2::suffix_match_len(&lhs, &rhs), 2);

    let lhs = DNSString2::new("www.example.org");
    let rhs = DNSString2::new("www.example.org");
    assert_eq!(DNSString2::suffix_match_len(&lhs, &rhs), 3);
}

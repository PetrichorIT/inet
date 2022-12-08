use super::*;
use crate::{FromBytestream, IntoBytestream};

#[test]
fn dns_string_from_str() {
    let dns = DNSString::new("www.example.com");
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "example");

    let dns = DNSString::new("www.example.com.");
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "example");

    let dns = DNSString::new("www.example.com".to_string());
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "example");

    let dns = DNSString::new("www.example.com.".to_string());
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "example");

    let dns = DNSString::new("mailserver.default.org.");
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "default");

    let dns = DNSString::new("www.a.bzgtv");
    assert_eq!(dns.labels(), 3);
    assert_eq!(dns.label(1), "a");

    let dns = DNSString::new("a.a.uri.a.example.com.");
    assert_eq!(dns.labels(), 6);
    assert_eq!(dns.label(1), "a");

    let dns = DNSString::new("a.a.uri.a.example.com:8000");
    assert_eq!(dns.labels(), 6);
    assert_eq!(dns.label(1), "a");

    let dns = DNSString::new("a.a.uri.a.example.com:8000.");
    assert_eq!(dns.labels(), 6);
    assert_eq!(dns.label(1), "a");

    let dns = DNSString::new("");
    assert_eq!(dns.labels(), 0);
}

#[test]
#[should_panic]
fn dns_string_from_non_ascii() {
    let _dns = DNSString::new("www.😀.de");
}

#[test]
#[should_panic]
fn dns_string_from_empty_label() {
    let _dns = DNSString::new("www..de");
}

#[test]
#[should_panic]
fn dns_string_from_non_network_forbidden_char() {
    let _dns = DNSString::new("www.a#a.de");
}

#[test]
#[should_panic]
fn dns_string_from_non_network_missplaced_char() {
    let _dns = DNSString::new("www.aa-.de");
}

#[test]
fn dns_string_parsing() {
    let inp = DNSString::new("www.example.com");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString::new("asg-erfurt.de");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString::new("a.b.c.www.example.com:800");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString::new("cdde.aaoa-adad.com.");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString::new("www.out.out.out.com:80.");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);

    let inp = DNSString::new("www.example.com");
    let bytes = inp.into_buffer().unwrap();
    let out = DNSString::from_buffer(bytes).unwrap();
    assert_eq!(inp, out);
}

#[test]
fn dns_string_suffix_checks() {
    let lhs = DNSString::new("www.example.org");
    let rhs = DNSString::new("n0.NIZ.org");
    assert_eq!(DNSString::suffix_match_len(&lhs, &rhs), 1);

    let lhs = DNSString::new("a.b.c.e.www.example.org");
    let rhs = DNSString::new("n0.NIZ.org");
    assert_eq!(DNSString::suffix_match_len(&lhs, &rhs), 1);

    let lhs = DNSString::new("www.example.org");
    let rhs = DNSString::new("www.example.oirg");
    assert_eq!(DNSString::suffix_match_len(&lhs, &rhs), 0);

    let lhs = DNSString::new("www.example.org");
    let rhs = DNSString::new("n0.example.org");
    assert_eq!(DNSString::suffix_match_len(&lhs, &rhs), 2);

    let lhs = DNSString::new("www.example.org");
    let rhs = DNSString::new("www.example.org");
    assert_eq!(DNSString::suffix_match_len(&lhs, &rhs), 3);
}

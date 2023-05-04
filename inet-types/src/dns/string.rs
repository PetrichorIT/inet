#![allow(clippy::cast_possible_wrap)]

use crate::{FromBytestream, IntoBytestream};
use bytestream::{ByteOrder::BigEndian, StreamReader};
use std::{
    fmt::Display,
    io::{Cursor, Write},
    ops::Deref,
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSString {
    string: String,
    labels: Vec<usize>,
}

impl DNSString {
    /// Converts a string into a dns encoded string.
    ///
    /// Node that this constructor removes port specifications
    /// and adds trailing dots if nessecary
    ///
    /// # Panics
    ///
    /// If the provided string is not dns encodable (ASCII + max u8 chars per element)
    #[must_use]
    pub fn new(string: impl AsRef<str>) -> Self {
        let string = string.as_ref();
        let split = string.split(':').collect::<Vec<_>>();
        let string = match split.len() {
            1 | 2 => split[0],
            _ => panic!("Invalid network name for DNSString encoding"),
        };

        let mut string = string.to_string().to_ascii_lowercase();

        if !string.ends_with('.') {
            string.push('.');
        }

        // Empty stirng
        if string.len() == 1 {
            return Self {
                string,
                labels: Vec::new(),
            };
        }

        assert!(string.is_ascii());
        assert!(
            string
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '@'),
            "Failed to encoding DNSString: '{string}' contains invalid characters"
        );

        let mut labels = Vec::with_capacity(string.len() + string.len() / 4);
        let mut chars = string.chars();
        for i in 0..string.len() {
            let c = chars.next().unwrap();
            if c == '.' {
                // current dot - first char of last label
                let label_len = i - labels.last().map_or(0, |v| *v + 1);
                assert!(label_len != 0, "Invalid empty label for DNSString encoding");
                labels.push(i);
            }
        }

        let this = Self { string, labels };
        for i in 0..this.labels() {
            let label = this.label(i);
            assert!(!label.ends_with('-') && !label.starts_with('-'));
        }

        this
    }

    #[must_use]
    pub fn labels(&self) -> usize {
        self.labels.len()
    }

    #[must_use]
    pub fn label(&self, i: usize) -> &str {
        let label_end = self.labels[i];
        let label_start = if i == 0 { 0 } else { self.labels[i - 1] + 1 };
        &self.string[label_start..label_end]
    }

    #[must_use]
    pub fn suffix_match_len(lhs: &Self, rhs: &Self) -> usize {
        let mut l = lhs.labels() as isize - 1;
        let mut r = rhs.labels() as isize - 1;
        let mut c = 0;
        while l >= 0 && r >= 0 {
            if lhs.label(l as usize) != rhs.label(r as usize) {
                break;
            }
            c += 1;
            l -= 1;
            r -= 1;
        }
        c
    }

    #[must_use]
    pub fn suffix(&self, i: usize) -> &str {
        let label_start = if i == 0 { 0 } else { self.labels[i - 1] + 1 };
        &self.string[label_start..]
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.string
    }
}

impl Display for DNSString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.string.fmt(f)
    }
}

impl Deref for DNSString {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.string
    }
}

impl IntoBytestream for DNSString {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        for i in 0..self.labels() {
            let label_str = self.label(i);
            bytestream.write_all(&[label_str.len() as u8])?;
            bytestream.write_all(label_str.as_bytes())?;
        }
        bytestream.write_all(&[0])?;
        Ok(())
    }
}

impl FromBytestream for DNSString {
    type Error = std::io::Error;
    fn from_bytestream(bytestream: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, Self::Error> {
        let mut string = String::new();
        let mut labels = Vec::new();
        loop {
            let label = u8::read_from(bytestream, BigEndian)?;
            if label == 0 {
                break;
            }
            for _ in 0..label {
                string.push(u8::read_from(bytestream, BigEndian)? as char);
            }
            string.push('.');
            labels.push(string.len() - 1);
        }

        if string.is_empty() {
            string.push('.');
            labels.push(1);
        }

        Ok(Self { string, labels })
    }
}

impl<T: AsRef<str>> From<T> for DNSString {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl FromStr for DNSString {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::DNSString;
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
        let bytes = inp.to_buffer().unwrap();
        let out = DNSString::from_buffer(bytes).unwrap();
        assert_eq!(inp, out);

        let inp = DNSString::new("asg-erfurt.de");
        let bytes = inp.to_buffer().unwrap();
        let out = DNSString::from_buffer(bytes).unwrap();
        assert_eq!(inp, out);

        let inp = DNSString::new("a.b.c.www.example.com:800");
        let bytes = inp.to_buffer().unwrap();
        let out = DNSString::from_buffer(bytes).unwrap();
        assert_eq!(inp, out);

        let inp = DNSString::new("cdde.aaoa-adad.com.");
        let bytes = inp.to_buffer().unwrap();
        let out = DNSString::from_buffer(bytes).unwrap();
        assert_eq!(inp, out);

        let inp = DNSString::new("www.out.out.out.com:80.");
        let bytes = inp.to_buffer().unwrap();
        let out = DNSString::from_buffer(bytes).unwrap();
        assert_eq!(inp, out);

        let inp = DNSString::new("www.example.com");
        let bytes = inp.to_buffer().unwrap();
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
}

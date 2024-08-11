#![allow(clippy::cast_possible_wrap)]

use bytepack::{BytestreamReader, BytestreamWriter, FromBytestream, ReadBytesExt, ToBytestream};
use std::{fmt::Display, io::Write, ops::Deref, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsString {
    string: String,
    labels: Vec<usize>,
    relative: bool,
}

impl DnsString {
    pub fn from_zonefile_definition(raw: &str, origin: &DnsString) -> Self {
        if raw == "@" {
            origin.clone()
        } else {
            let path = DnsString::new(raw);
            if path.is_relative() {
                path.with_root(origin)
            } else {
                path
            }
        }
    }

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

        let string = string.to_string().to_ascii_lowercase();
        if string.is_empty() {
            return Self {
                string,
                labels: Vec::new(),
                relative: true,
            };
        }

        let relative = !string.ends_with('.');

        // Empty stirng
        if string.len() == 1 {
            return Self {
                string,
                labels: Vec::new(),
                relative,
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
        for i in 0..(string.len() + if relative { 1 } else { 0 }) {
            let c = chars.next();
            if c == Some('.') || c.is_none() {
                // current dot - first char of last label
                let label_len = i - labels.last().map_or(0, |v| *v + 1);
                assert!(label_len != 0, "Invalid empty label for DNSString encoding");
                labels.push(i);
            }
        }

        let this = Self {
            string,
            labels,
            relative,
        };
        for i in 0..this.labels() {
            let label = this.label(i);
            assert!(!label.ends_with('-') && !label.starts_with('-'));
        }

        this
    }

    pub fn is_relative(&self) -> bool {
        self.relative
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
    pub fn prefix(&self, i: usize) -> &str {
        let label_end = if i == 0 { 0 } else { self.labels[i - 1] + 1 };
        &self.string[..label_end]
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.string
    }

    pub fn with_root(&self, root: &DnsString) -> DnsString {
        assert!(self.is_relative());

        // Find applicable suffix
        for k in (1..root.labels() + 1).rev() {
            let suffix = root.prefix(k);
            dbg!(&self.string, suffix.trim_end_matches('.'));
            if self.string.ends_with(suffix.trim_end_matches('.')) {
                return DnsString::new(self.as_str().to_string() + "." + root.suffix(k));
            }
        }

        // TODO: this can be done easier
        DnsString::new(self.as_str().to_string() + "." + root.as_str())
    }
}

impl Display for DnsString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.string.fmt(f)
    }
}

impl Deref for DnsString {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.string
    }
}

impl PartialOrd for DnsString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.string.partial_cmp(&other.string)
    }
}

impl Ord for DnsString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.string.cmp(&other.string)
    }
}

impl ToBytestream for DnsString {
    type Error = std::io::Error;
    fn to_bytestream(&self, bytestream: &mut BytestreamWriter) -> Result<(), Self::Error> {
        for i in 0..self.labels() {
            let label_str = self.label(i);
            bytestream.write_all(&[label_str.len() as u8])?;
            bytestream.write_all(label_str.as_bytes())?;
        }
        bytestream.write_all(&[0])?;
        Ok(())
    }
}

impl FromBytestream for DnsString {
    type Error = std::io::Error;
    fn from_bytestream(stream: &mut BytestreamReader) -> Result<Self, Self::Error> {
        let mut string = String::new();
        let mut labels = Vec::new();
        loop {
            let label = stream.read_u8()?;
            if label == 0 {
                break;
            }
            for _ in 0..label {
                string.push(stream.read_u8()? as char);
            }
            string.push('.');
            labels.push(string.len() - 1);
        }

        if string.is_empty() {
            string.push('.');
            labels.push(1);
        }

        Ok(Self {
            string,
            labels,
            relative: false,
        })
    }
}

impl<T: AsRef<str>> From<T> for DnsString {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl FromStr for DnsString {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::DnsString;
    use bytepack::{FromBytestream, ToBytestream};

    #[test]
    fn with_root() {
        let root = DnsString::new("example.com.");

        // Paths with matching suffixes are not changed, even if realtive
        assert_eq!(
            DnsString::new("www.example.com").with_root(&root),
            DnsString::new("www.example.com.")
        );
        assert_eq!(
            DnsString::new("www.example").with_root(&root),
            DnsString::new("www.example.com.")
        );

        // No match mean full addition
        assert_eq!(
            DnsString::new("www").with_root(&root),
            DnsString::new("www.example.com.")
        );

        // Pseudo match
        assert_eq!(
            DnsString::new("com").with_root(&root),
            DnsString::new("com.example.com.")
        );
    }

    #[test]
    fn dns_string_from_str() {
        let dns = DnsString::new("www.example.com");
        assert_eq!(dns.labels(), 3);
        assert_eq!(dns.label(1), "example");

        let dns = DnsString::new("www.example.com.");
        assert_eq!(dns.labels(), 3);
        assert_eq!(dns.label(1), "example");

        let dns = DnsString::new("www.example.com".to_string());
        assert_eq!(dns.labels(), 3);
        assert_eq!(dns.label(1), "example");

        let dns = DnsString::new("www.example.com.".to_string());
        assert_eq!(dns.labels(), 3);
        assert_eq!(dns.label(1), "example");

        let dns = DnsString::new("mailserver.default.org.");
        assert_eq!(dns.labels(), 3);
        assert_eq!(dns.label(1), "default");

        let dns = DnsString::new("www.a.bzgtv");
        assert_eq!(dns.labels(), 3);
        assert_eq!(dns.label(1), "a");

        let dns = DnsString::new("a.a.uri.a.example.com.");
        assert_eq!(dns.labels(), 6);
        assert_eq!(dns.label(1), "a");

        let dns = DnsString::new("a.a.uri.a.example.com:8000");
        assert_eq!(dns.labels(), 6);
        assert_eq!(dns.label(1), "a");

        let dns = DnsString::new("a.a.uri.a.example.com:8000.");
        assert_eq!(dns.labels(), 6);
        assert_eq!(dns.label(1), "a");

        let dns = DnsString::new("");
        assert_eq!(dns.labels(), 0);
    }

    #[test]
    #[should_panic]
    fn dns_string_from_non_ascii() {
        let _dns = DnsString::new("www.😀.de");
    }

    #[test]
    #[should_panic]
    fn dns_string_from_empty_label() {
        let _dns = DnsString::new("www..de");
    }

    #[test]
    #[should_panic]
    fn dns_string_from_non_network_forbidden_char() {
        let _dns = DnsString::new("www.a#a.de");
    }

    #[test]
    #[should_panic]
    fn dns_string_from_non_network_missplaced_char() {
        let _dns = DnsString::new("www.aa-.de");
    }

    #[test]
    fn dns_string_parsing() {
        let inp = DnsString::new("www.example.com.");
        let bytes = inp.to_vec().unwrap();
        let out = DnsString::read_from_slice(&mut &bytes[..]).unwrap();
        assert_eq!(inp, out);

        let inp = DnsString::new("asg-erfurt.de.");
        let bytes = inp.to_vec().unwrap();
        let out = DnsString::read_from_slice(&mut &bytes[..]).unwrap();
        assert_eq!(inp, out);

        let inp = DnsString::new("a.b.c.www.example.com.:800");
        let bytes = inp.to_vec().unwrap();
        let out = DnsString::read_from_slice(&mut &bytes[..]).unwrap();
        assert_eq!(inp, out);

        let inp = DnsString::new("cdde.aaoa-adad.com.");
        let bytes = inp.to_vec().unwrap();
        let out = DnsString::read_from_slice(&mut &bytes[..]).unwrap();
        assert_eq!(inp, out);

        let inp = DnsString::new("www.out.out.out.com.:80.");
        let bytes = inp.to_vec().unwrap();
        let out = DnsString::read_from_slice(&mut &bytes[..]).unwrap();
        assert_eq!(inp, out);

        let inp = DnsString::new("www.example.com.");
        let bytes = inp.to_vec().unwrap();
        let out = DnsString::read_from_slice(&mut &bytes[..]).unwrap();
        assert_eq!(inp, out);
    }

    #[test]
    fn dns_string_suffix_checks() {
        let lhs = DnsString::new("www.example.org");
        let rhs = DnsString::new("n0.NIZ.org");
        assert_eq!(DnsString::suffix_match_len(&lhs, &rhs), 1);

        let lhs = DnsString::new("a.b.c.e.www.example.org");
        let rhs = DnsString::new("n0.NIZ.org");
        assert_eq!(DnsString::suffix_match_len(&lhs, &rhs), 1);

        let lhs = DnsString::new("www.example.org");
        let rhs = DnsString::new("www.example.oirg");
        assert_eq!(DnsString::suffix_match_len(&lhs, &rhs), 0);

        let lhs = DnsString::new("www.example.org");
        let rhs = DnsString::new("n0.example.org");
        assert_eq!(DnsString::suffix_match_len(&lhs, &rhs), 2);

        let lhs = DnsString::new("www.example.org");
        let rhs = DnsString::new("www.example.org");
        assert_eq!(DnsString::suffix_match_len(&lhs, &rhs), 3);
    }
}

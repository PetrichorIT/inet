use std::{
    fmt::{Debug, Display},
    io::{self, Read, Write},
    str::FromStr,
};

use bytes_io::{BytesReader, BytesWriter, FromBytes, ReadBytesExt, ToBytes, WriteBytesExt};

/// The string representation of a DNS name, in DNS packet encoding
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsString {
    labels: Vec<String>,
    relative: bool,
}

impl DnsString {
    pub const fn empty() -> Self {
        Self {
            labels: Vec::new(),
            relative: false,
        }
    }

    pub fn from_zonefile(raw: &str, origin: &DnsString) -> io::Result<Self> {
        if raw == "@" {
            Ok(origin.clone())
        } else {
            let path = DnsString::from_str(raw)?;
            if path.is_relative() {
                Ok(path.with_root(origin))
            } else {
                Ok(path)
            }
        }
    }

    pub fn is_relative(&self) -> bool {
        self.relative
    }

    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    pub fn as_string(&self) -> String {
        format!("{self}")
    }

    pub fn has_parent(&self, parent: &DnsString) -> bool {
        assert!(self.labels().len() >= parent.labels().len());
        let len = parent.labels().len();
        self.labels[(self.labels().len() - len)..] == parent.labels
    }

    pub fn truncated(&self, new_len: usize) -> DnsString {
        assert!(new_len <= self.labels().len());
        let start_index = self.labels().len() - new_len;
        DnsString {
            labels: Vec::from(&self.labels[start_index..]),
            relative: self.relative,
        }
    }

    pub fn suffix_match_len(&self, other: &DnsString) -> usize {
        let zipped = self.labels.iter().rev().zip(other.labels.iter().rev());
        for (i, (lhs, rhs)) in zipped.enumerate() {
            if lhs != rhs {
                return i;
            }
        }
        self.labels().len().min(other.labels().len())
    }

    pub fn with_root(&self, root: &DnsString) -> DnsString {
        assert!(
            self.is_relative(),
            "with_root can only be called on relative dns strings"
        );
        assert!(!root.is_relative(), "Roots must be absolute '{root}'");

        for cmp_size in (1..=root.labels().len()).rev() {
            let suffix_index = self.labels().len().saturating_sub(cmp_size);
            let is_match = self.labels[suffix_index..] == root.labels[..cmp_size];
            if is_match {
                return DnsString {
                    labels: self
                        .labels
                        .iter()
                        .chain(root.labels[cmp_size..].iter())
                        .cloned()
                        .collect(),
                    relative: false,
                };
            }
        }

        DnsString {
            labels: self
                .labels
                .iter()
                .chain(root.labels.iter())
                .cloned()
                .collect(),
            relative: false,
        }
    }
}

impl FromStr for DnsString {
    type Err = io::Error;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let split = string.split(':').collect::<Vec<_>>();
        let string = match split.len() {
            1 | 2 => split[0],
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Non compliant DNS String",
                ))
            }
        };

        let string = string.to_string().to_ascii_lowercase();
        if string.is_empty() {
            return Ok(Self {
                labels: Vec::new(),
                relative: true,
            });
        }

        // Empty stirng
        if string == "." {
            return Ok(Self {
                labels: Vec::new(),
                relative: false,
            });
        }

        let relative = !string.ends_with('.');
        let trunc_len = if relative { 0 } else { 1 };
        let string_without_last_dot = &string[..(string.len() - trunc_len)];

        let labels = string_without_last_dot
            .split('.')
            .map(|s| {
                if !s.is_ascii()
                    || !string
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '@')
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Failed to encoding DNSString: '{string}' contains invalid characters"
                        ),
                    ));
                }
                if s.ends_with('-') || s.starts_with('|') {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Failed to encoding DNSString: '{string}' contains labels delimited by '-'"
                        ),
                    ));
                }

                Ok(s.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { labels, relative })
    }
}

impl Debug for DnsString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl Display for DnsString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            self.labels.join("."),
            if self.relative { "" } else { "." }
        )
    }
}

impl PartialOrd for DnsString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_string().cmp(&other.to_string()))
    }
}

impl Ord for DnsString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl ToBytes for DnsString {
    type Error = std::io::Error;
    fn to_bytes(&self, bytestream: &mut BytesWriter) -> Result<(), Self::Error> {
        for label in self.labels() {
            bytestream.write_u8(label.len() as u8)?;
            bytestream.write_all(label.as_bytes())?;
        }
        bytestream.write_u8(0)?;
        Ok(())
    }
}

impl FromBytes for DnsString {
    type Error = std::io::Error;
    fn from_bytes(stream: &mut BytesReader) -> Result<Self, Self::Error> {
        let mut labels = Vec::new();
        loop {
            let label_len = stream.read_u8()?;
            if label_len == 0 {
                break;
            }
            let mut bytes = vec![0; label_len as usize];
            stream.read_exact(&mut bytes)?;
            labels.push(String::from_utf8(bytes).map_err(io::Error::other)?);
        }

        Ok(Self {
            labels,
            relative: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes_io::assert_encoding_e2e;

    use super::*;

    #[test]
    fn truncate() {
        let value: DnsString = "www.example.org.".parse().unwrap();
        assert_eq!(value.truncated(3), "www.example.org.".parse().unwrap());
        assert_eq!(value.truncated(2), "example.org.".parse().unwrap());
        assert_eq!(value.truncated(1), "org.".parse().unwrap());
    }

    #[test]
    fn with_roota() {
        let value: DnsString = "ns.www.example.org".parse().unwrap();
        let root: DnsString = "www.example.org.".parse().unwrap();

        assert_eq!(
            value.with_root(&root),
            "ns.www.example.org.".parse().unwrap()
        );
    }

    #[test]
    fn byte_encoding_e2e() -> io::Result<()> {
        let raws = ["www.example.org.", "a.b.c.www.example.org.", "org.", "."];
        for raw in raws {
            let initial = DnsString::from_str(raw)?;
            let reparsed = DnsString::read_from(&mut initial.write_to_bytes()?)?;
            assert_eq!(initial, reparsed);
        }
        Ok(())
    }

    #[test]
    fn e2e_encoding() -> io::Result<()> {
        assert_encoding_e2e::<DnsString, _>(&[
            ".".parse()?,
            "www.example.org.".parse()?,
            "a.b.c.www.example.org.".parse()?,
            "org.".parse()?,
            "www.example.org.".parse()?,
            "www.abcd-dasd.a.org.".parse()?,
            "utf.a.a.v.ad.ad.ad.ad.d.org.".parse()?,
            "www.abcd-dasd.a.org.".parse()?,
        ]);
        Ok(())
    }
}

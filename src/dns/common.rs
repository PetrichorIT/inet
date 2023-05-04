use bytestream::{ByteOrder::BigEndian, StreamReader};
use inet_types::{FromBytestream, IntoBytestream};
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
    pub fn new(string: impl AsRef<str>) -> Self {
        let string = string.as_ref();
        let split = string.split(":").collect::<Vec<_>>();
        let string = match split.len() {
            1 | 2 => split[0],
            _ => panic!("Invalid network name for DNSString encoding"),
        };

        let mut string = string.to_string().to_ascii_lowercase();

        if !string.ends_with(".") {
            string.push('.')
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
            "Failed to encoding DNSString: '{}' contains invalid characters",
            string
        );

        let mut labels = Vec::with_capacity(string.len() + string.len() / 4);
        let mut chars = string.chars();
        for i in 0..string.len() {
            let c = chars.next().unwrap();
            if c == '.' {
                // current dot - first char of last label
                let label_len = i - labels.last().map(|v| *v + 1).unwrap_or(0);
                if label_len == 0 {
                    panic!("Invalid empty label for DNSString encoding")
                }
                labels.push(i);
            }
        }

        let this = Self { string, labels };
        for i in 0..this.labels() {
            let label = this.label(i);
            assert!(!label.ends_with("-") && !label.starts_with("-"))
        }

        this
    }

    pub fn labels(&self) -> usize {
        self.labels.len()
    }

    pub fn label(&self, i: usize) -> &str {
        let label_end = self.labels[i];
        let label_start = if i == 0 { 0 } else { self.labels[i - 1] + 1 };
        &self.string[label_start..label_end]
    }

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

    pub fn suffix(&self, i: usize) -> &str {
        let label_start = if i == 0 { 0 } else { self.labels[i - 1] + 1 };
        &self.string[label_start..]
    }

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
    fn into_bytestream(&self, bytestream: &mut impl Write) -> Result<(), Self::Error> {
        for i in 0..self.labels() {
            let label_str = self.label(i);
            bytestream.write(&[label_str.len() as u8])?;
            bytestream.write(label_str.as_bytes())?;
        }
        bytestream.write(&[0])?;
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

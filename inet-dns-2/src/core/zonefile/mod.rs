use std::{io, rc::Rc, str::FromStr};

use super::{DnsResourceRecord, DnsString, ResourceRecordClass, ResourceRecordTyp};

pub struct Zonefile {
    pub records: Vec<DnsResourceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZonefileLineRecord {
    pub origin: Rc<DnsString>,
    pub name: DnsString,
    pub ttl: u32,
    pub class: ResourceRecordClass,
    pub typ: ResourceRecordTyp,
    pub rdata: String,
}

#[derive(Debug)]
struct Reader {
    origin: Rc<DnsString>,

    last_ttl: Option<u32>,
    default_ttl: Option<u32>,

    last_name: Option<DnsString>,
}

impl Reader {
    fn name(&self) -> DnsString {
        self.last_name.clone().unwrap_or(DnsString::new(""))
    }
    fn ttl(&self) -> u32 {
        self.default_ttl.or(self.last_ttl).unwrap_or(0)
    }
}

impl FromStr for Zonefile {
    type Err = io::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s
            .lines()
            .map(|l| l.split_once(';').map(|(lhs, _)| lhs).unwrap_or(l));

        let mut reader = Reader {
            origin: Rc::new(DnsString::new("")),

            last_ttl: None,
            default_ttl: None,

            last_name: None,
        };

        let mut records = Vec::new();

        while let Some(line) = eat_line(&mut lines) {
            if line.trim().is_empty() {
                continue;
            }

            if line.starts_with('$') {
                read_directive(line, &mut reader)?;
                continue;
            }

            let starts_with_whitespace =
                line.chars().next().expect("no empty lines").is_whitespace();

            let mut parts = line
                .split_whitespace()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();

            // There are two allowed layouts
            // name | ttl | class | type | rdata
            // name | class | ttl | type | rdata

            // read one entry
            let name = if starts_with_whitespace {
                reader.name()
            } else {
                let raw = parts.remove(0);
                DnsString::from_zonefile_definition(&raw, &*reader.origin)
            };

            reader.last_name = Some(name.clone());

            // ready up to two entries
            let first_str = &parts[0];
            let second_str = &parts[1];

            let (ttl, class, skip) = if let Ok(class) = first_str.parse() {
                // either "class | ttl" or "class | blank"
                if let Ok(ttl) = second_str.parse() {
                    (ttl, class, 2)
                } else {
                    (reader.ttl(), class, 1)
                }
            } else {
                // either "ttl | class" or "class" or ""
                if let Ok(ttl) = first_str.parse() {
                    if let Ok(class) = second_str.parse() {
                        (ttl, class, 2)
                    } else {
                        (ttl, ResourceRecordClass::IN, 1)
                    }
                } else {
                    (reader.ttl(), ResourceRecordClass::IN, 0)
                }
            };

            reader.last_ttl = Some(ttl);

            let parts = &parts[skip..];

            // read typ
            let typ = parts[0].parse::<ResourceRecordTyp>()?;
            let parts = &parts[1..];

            // rdata
            let mut rdata = parts.iter().fold(String::new(), |a, b| a + " " + b);
            rdata.remove(0);

            records.push(ZonefileLineRecord {
                origin: reader.origin.clone(),
                name,
                typ,
                ttl,
                class,
                rdata,
            });
        }
        Ok(Self {
            records: records
                .into_iter()
                .map(DnsResourceRecord::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

fn read_directive(line: String, reader: &mut Reader) -> io::Result<()> {
    let parts = line
        .trim_start_matches('$')
        .split_once(';')
        .map(|(lhs, _)| lhs)
        .unwrap_or(line.as_str())
        .split_whitespace()
        .collect::<Vec<_>>();

    if parts.len() != 2 {
        return Err(io::Error::other("invalid stmt"));
    }

    match *&parts[0] {
        "$TTL" => reader.default_ttl = Some(parts[1].parse().map_err(io::Error::other)?),
        "$ORIGIN" => reader.origin = Rc::new(DnsString::from(parts[1])),
        _ => {}
    }

    Ok(())
}

fn eat_line(lines: &mut dyn Iterator<Item = &str>) -> Option<String> {
    let mut buffer = String::new();
    let mut depth = 0;
    for line in lines {
        buffer.push_str(line);
        depth += line.chars().filter(|c| *c == '(').count();
        depth -= line.chars().filter(|c| *c == ')').count();
        if depth == 0 {
            return Some(buffer.replace("\\.", "."));
        }
    }
    None
}

use super::types::{DNSClass, DNSResourceRecord, DNSSOAResourceRecord, DNSString, DNSType};
use bytepack::ToBytestream;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSZoneFile {
    pub(super) zone: DNSString,
    pub(super) soa: DNSSOAResourceRecord,
    pub(super) records: Vec<DNSResourceRecord>,
}

impl DNSZoneFile {
    pub fn new(
        zone: impl Into<DNSString>,
        zone_file_dir: impl AsRef<str>,
    ) -> std::io::Result<Self> {
        let zone: DNSString = zone.into();
        let mut path = PathBuf::from(zone_file_dir.as_ref());
        path.push(format!("{}dns", *zone));

        let file = File::open(path)?;
        let file = BufReader::new(file);

        let mut this = Self {
            zone,
            soa: DNSSOAResourceRecord {
                name: DNSString::new(""),
                class: DNSClass::Internet,
                ttl: 0,
                mname: DNSString::new(""),
                rname: DNSString::new(""),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            },
            records: Vec::new(),
        };

        let mut lines = file.lines();
        while let Some(Ok(line)) = lines.next() {
            if line.trim().starts_with("%") {
                continue;
            }
            let split = line.split(" ").collect::<Vec<_>>();
            if split.len() < 5 {
                continue;
            }

            match split[3] {
                "SOA" => {
                    this.soa.name = split[0].into();
                    this.soa.ttl = split[1].parse().unwrap();
                    this.soa.class = split[2].parse().unwrap();
                    // this.soa.typ
                    this.soa.mname = split[4].into();
                    this.soa.rname = split[5].into();

                    // timestamps
                    let split = line.split(&['(', ')']).collect::<Vec<_>>();
                    assert_eq!(split.len(), 3);
                    let split = split[1].split(" ").collect::<Vec<_>>();
                    assert_eq!(split.len(), 5);
                    this.soa.serial = split[0].parse().unwrap();
                    this.soa.refresh = split[1].parse().unwrap();
                    this.soa.retry = split[2].parse().unwrap();
                    this.soa.expire = split[3].parse().unwrap();
                    this.soa.minimum = split[4].parse().unwrap();
                    break;
                }
                _ => continue,
            }
        }

        assert!(this.soa.serial != 0);

        for line in lines {
            let Ok(line) = line else { continue };
            if line.trim().starts_with("%") {
                continue;
            }

            let split = line.split(" ").collect::<Vec<_>>();
            if split.len() < 5 {
                continue;
            }

            let typ = split[3].parse::<DNSType>().unwrap();
            match typ {
                DNSType::A => {
                    let ip = split[4].parse::<Ipv4Addr>().unwrap();
                    this.records.push(DNSResourceRecord {
                        name: split[0].into(),
                        typ,
                        class: split[2].parse().unwrap(),
                        ttl: split[1].parse().unwrap(),
                        rdata: Vec::from(ip.octets()),
                    })
                }
                DNSType::AAAA => {
                    let ip = split[4].parse::<Ipv6Addr>().unwrap();
                    this.records.push(DNSResourceRecord {
                        name: split[0].into(),
                        typ,
                        class: split[2].parse().unwrap(),
                        ttl: split[1].parse().unwrap(),
                        rdata: Vec::from(ip.octets()),
                    })
                }
                DNSType::NS => this.records.push(DNSResourceRecord {
                    name: split[0].into(),
                    typ,
                    class: split[2].parse().unwrap(),
                    ttl: split[1].parse().unwrap(),
                    rdata: DNSString::new(split[4]).to_vec().unwrap(),
                }),
                DNSType::PTR => this.records.push(DNSResourceRecord {
                    name: split[0].into(),
                    typ,
                    class: split[2].parse().unwrap(),
                    ttl: split[1].parse().unwrap(),
                    rdata: DNSString::new(split[4]).to_vec().unwrap(),
                }),
                _ => unimplemented!(),
            }
        }

        Ok(this)
    }
}

use std::{
    collections::HashMap,
    fs::{read_dir, read_to_string},
    io,
    str::FromStr,
};

use des::{prelude::*, time::sleep};
use inet::{
    tcp::{TcpListener, TcpStream},
    utils::SimpleSim,
};
use inet_dns::{
    adapters::{Base, UdpAdapter},
    client::resolve,
    core::{
        AResourceRecord, DnsString, NsResourceRecord, Question, QuestionClass, QuestionTyp,
        ZoneResolver, Zonefile,
    },
    server::{IterativeNameserver, TransportMedium},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    spawn,
};

const DOMAINS: [&str; 15] = [
    "www.example.org",
    "ftp.example.org",
    "info.example.org",
    "status.info.example.org",
    "stats.example.org",
    "www.tu-ilmenau.de",
    "prakinf.telematik.tu-ilmenau.de",
    "os.tu-ilmenau.de",
    "www.bund.de",
    "id.bund.de",
    "www.admin.org",
    "recovery.admin.org",
    "www.test.org",
    "ftp.test.org",
    "status.test.org",
];

#[test]
fn run() -> Result<(), RuntimeError> {
    let zonefiles = read_dir("tests/zonefiles")?
        .flatten()
        .flat_map(|path| {
            Ok::<_, io::Error>((
                path.path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .trim_end_matches(".dns")
                    .to_string(),
                Zonefile::from_str(&read_to_string(path.path())?)?,
            ))
        })
        .collect::<Vec<_>>();

    let iter = IterativeNameserver::primary(
        zonefiles
            .iter()
            .flat_map(|(_, zf)| ZoneResolver::new(zf.clone()))
            .collect(),
    );

    let domain_mapping = DOMAINS
        .iter()
        .map(|domain| {
            let resp = iter
                .query(&Question {
                    qname: domain.parse().unwrap(),
                    qclass: QuestionClass::IN,
                    qtyp: QuestionTyp::A,
                })
                .unwrap();
            let addr = resp
                .anwsers
                .first()
                .unwrap()
                .as_any()
                .downcast_ref::<AResourceRecord>()
                .unwrap()
                .addr;
            (*domain, addr)
        })
        .collect::<HashMap<_, _>>();

    let nameserver_mappings = zonefiles
        .iter()
        .flat_map(|(domain, zf)| {
            iter.query(&Question {
                qname: domain.parse().unwrap(),
                qclass: QuestionClass::IN,
                qtyp: QuestionTyp::NS,
            })
            .unwrap()
            .anwsers
            .into_iter()
            .map(|entry| {
                let ns = entry.as_any().downcast_ref::<NsResourceRecord>().unwrap();
                let addr = iter
                    .query(&Question {
                        qname: ns.nameserver.clone(),
                        qclass: QuestionClass::IN,
                        qtyp: QuestionTyp::A,
                    })
                    .unwrap()
                    .anwsers[0]
                    .as_any()
                    .downcast_ref::<AResourceRecord>()
                    .unwrap()
                    .addr;

                (ns.domain.clone(), ns.nameserver.clone(), addr, zf.clone())
            })
        })
        .collect::<Vec<_>>();

    let mut sim = SimpleSim::new(inet::stack(resolve));

    for (domain, addr) in domain_mapping {
        sim.node_with_addr(
            &format!("server:{domain}"),
            &addr.to_string(),
            move || async move {
                let list = TcpListener::bind("0.0.0.0:80").await?;
                loop {
                    let accept = list.accept().await?;
                    spawn(async move {
                        let (mut stream, from) = accept;

                        let mut buf = [0; 512];
                        let n = stream.read(&mut buf).await?;
                        let s = String::from_utf8_lossy(&buf[..n]);
                        // let lookup = lookup_host((s.to_string(), 80)).await?.next().unwrap();
                        // assert_eq!(lookup.ip(), addr);
                        stream.write_all(&[42]).await?;

                        tracing::trace!("responded to new stream from {from:?} known as {s}");

                        Ok::<_, io::Error>(())
                    });
                }
            },
        );
    }

    for (domain, nameserver, addr, zf) in nameserver_mappings {
        sim.node_with_addr(&format!("dns:{nameserver}"), &addr.to_string(), move || {
            let zf = zf.clone();
            let name = domain.clone();
            async move {
                let server = IterativeNameserver::primary(vec![ZoneResolver::new(zf)?]);
                Base::new(server)
                    .set_root(name == DnsString::empty())
                    .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                    .deploy()
                    .await
            }
        });
    }

    for client in &["alice", "bob", "eve"] {
        sim.node_require_join(client, move || async move {
            sleep(Duration::from_secs(1)).await;

            for i in 0..100 {
                let domain = DOMAINS[random::<u64>() as usize % DOMAINS.len()];
                let mut stream = TcpStream::connect((domain, 80)).await?;
                stream.write_all(domain.as_bytes()).await?;
                let mut buf = [0; 64];
                let n = stream.read(&mut buf).await?;
                assert_eq!(n, 1);
                assert_eq!(buf[0], 42);

                tracing::info!("completed request {i}:'{domain}'");
            }

            Ok(())
        });
    }

    sim.run()
}

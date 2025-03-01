use std::str::FromStr;

use inet::test_util::SimpleSim;
use inet_dns_2::{
    client::dns_resolver,
    core::{DnsZoneResolver, Zonefile},
    server::{DnsIterativeNameserver, UdpBased},
};

const ZONE_FILE_ROOT: &str = include_str!("data/root.zone");
const ZONE_FILE_ORG: &str = include_str!("data/org.zone");
const ZONE_FILE_EXAMPLE_ORG: &str = include_str!("data/example.org.zone");

#[test]
fn test_integration() {
    let mut sim = SimpleSim::new();

    // Servers
    sim.node("192.168.2.10", || async {
        let zf = Zonefile::from_str(ZONE_FILE_ROOT)?;
        let zone = DnsZoneResolver::new(zf)?;
        let ns = DnsIterativeNameserver::new(vec![zone]);
        let mut server = UdpBased::new(ns).set_root();

        server.launch().await?;
        Ok(())
    });

    sim.node("192.168.2.20", || async {
        let zf = Zonefile::from_str(ZONE_FILE_ORG)?;
        let zone = DnsZoneResolver::new(zf)?;
        let ns = DnsIterativeNameserver::new(vec![zone]);
        let mut server = UdpBased::new(ns);

        server.launch().await?;
        Ok(())
    });

    sim.node("192.168.2.30", || async {
        let zf = Zonefile::from_str(ZONE_FILE_EXAMPLE_ORG)?;
        let zone = DnsZoneResolver::new(zf)?;
        let ns = DnsIterativeNameserver::new(vec![zone]);
        let mut server = UdpBased::new(ns);

        server.launch().await?;
        Ok(())
    });

    // Clients
    sim.node("192.168.2.101", || async {
        let lookup = dns_resolver("bob.example.org", 80).await;
        tracing::warn!("{lookup:?}");
        Ok(())
    });
    sim.node("192.168.2.102", || async { Ok(()) });

    let _ = sim.run();
}

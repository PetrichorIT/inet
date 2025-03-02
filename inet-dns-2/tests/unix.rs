use std::{str::FromStr, time::Duration};

use des::time::SimTime;
use inet::{dns::lookup_host, stack, test_util::SimpleSim};
use inet_dns_2::{
    client::{resolve, ClientResolver},
    core::{DnsZoneResolver, Zonefile},
    server::{DnsIterativeNameserver, UdpBased},
};

const ZONE_FILE_ROOT: &str = include_str!("data/root.zone");
const ZONE_FILE_ORG: &str = include_str!("data/org.zone");
const ZONE_FILE_EXAMPLE_ORG: &str = include_str!("data/example.org.zone");

#[test]
fn test_integration() {
    des::tracing::init();

    let mut sim = SimpleSim::new(stack(resolve));

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
        ClientResolver::default().launch()?;

        let t0 = SimTime::now();
        let _ = lookup_host(("bob.example.org.", 80)).await;
        let resolve_1 = t0.elapsed();

        let t0 = SimTime::now();
        let _ = lookup_host(("bob.example.org.", 80)).await;
        let resolve_2 = t0.elapsed();

        assert_eq!(resolve_2, Duration::ZERO);

        let t0 = SimTime::now();
        let _ = lookup_host(("alice.example.org.", 80)).await;
        let resolve_3 = t0.elapsed();

        assert!(resolve_3 < resolve_1);

        tracing::info!("DONE");

        Ok(())
    });
    sim.node("192.168.2.102", || async { Ok(()) });

    let _ = sim.run();
}

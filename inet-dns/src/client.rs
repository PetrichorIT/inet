//! A client resolver, to bind to [`inet::dns::set_dns_resolver`]

use std::{
    future::Future,
    io::{self, Result},
    net::{IpAddr, SocketAddr},
    pin::Pin,
};

use inet::ioctx;
use tokio::sync::{
    mpsc::{self, Sender},
    oneshot,
};

use crate::{
    adapters::{Base, LocalAdapter, UdpAdapter},
    core::{DnsString, Zonefile},
    server::{RecursiveNameserver, TransportMedium, all_root_ns},
};

/// A client resolver, using a locac adapter on a recursive DNS server
///
/// # Panics
///
/// Panics if the local resolver could not be initialized.
#[must_use]
pub fn resolve(
    host: &str,
    port: u16,
) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>>> + Send + 'static>> {
    let ext = ioctx().get_extension::<DnsExtension>();
    let tx = ext.with(|ext| ext.tx.clone());
    let tx = tx.unwrap_or_else(|| {
        let (tx, rx) = mpsc::channel(8);
        let ns = RecursiveNameserver::new(Zonefile::local())
            .expect("cannot fail")
            .with_roots(all_root_ns());
        let server = Base::new(ns)
            .with_adapter(TransportMedium::Local, LocalAdapter::new(rx))
            .with_adapter(TransportMedium::Udp, UdpAdapter::default().with_port(0));

        tracing::trace!("starting client resolver");
        tokio::spawn(server.deploy());

        ext.with(|ext| ext.tx = Some(tx.clone()));
        tx
    });

    let host = host.parse::<DnsString>();
    Box::pin(async move {
        let (req_tx, req_rx) = oneshot::channel();
        tx.send((host?, req_tx)).await.unwrap();

        Ok(req_rx
            .await
            .map_err(|_| io::Error::other("broke pipe"))??
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    })
}

#[derive(Debug, Default)]
pub struct DnsExtension {
    tx: Option<Sender<Request>>,
}

type Request = (DnsString, oneshot::Sender<Response>);
type Response = Result<Vec<IpAddr>>;

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use des::time::SimTime;
    use inet::{
        dns::{lookup_host, set_dns_resolver},
        utils::SimpleSim,
    };
    use serial_test::serial;

    use crate::{
        adapters::{Base, UdpAdapter},
        core::{Error, ResponseCode, ZoneResolver},
        server::IterativeNameserver,
    };

    use super::*;

    const ZONEFILE_ROOT: &str = include_str!("examples/root.zone");
    const ZONEFILE_ORG: &str = include_str!("examples/org.zone");
    const ZONEFILE_EXAMPLE_ORG: &str = include_str!("examples/example.org.zone");

    #[test]
    #[serial]
    fn resolver_integration_with_caching() {
        let mut sim = SimpleSim::new(inet::init);

        // Servers
        sim.node("192.168.2.10", || async {
            let zf = Zonefile::from_str(ZONEFILE_ROOT)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);
            Base::new(ns)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                .set_root(true)
                .deploy()
                .await
        });

        sim.node("192.168.2.20", || async {
            let zf = Zonefile::from_str(ZONEFILE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);

            Base::new(ns)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                .deploy()
                .await
        });

        sim.node("192.168.2.30", || async {
            let zf = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);
            Base::new(ns)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                .deploy()
                .await
        });

        // Clients
        sim.node_require_join("192.168.2.101", || async {
            set_dns_resolver(resolve)?;

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

    #[test]
    #[serial]
    fn resolver_will_fail_after_timeouts() {
        let mut sim = SimpleSim::new(inet::init);

        // Servers
        sim.node("192.168.2.10", || async {
            let zf = Zonefile::from_str(ZONEFILE_ROOT)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);
            Base::new(ns)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                .set_root(true)
                .deploy()
                .await
        });

        sim.node("192.168.2.20", || async {
            let zf = Zonefile::from_str(ZONEFILE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);
            Base::new(ns)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                .deploy()
                .await
        });

        sim.node("192.168.2.30", || async {
            let zf = Zonefile::from_str(ZONEFILE_EXAMPLE_ORG)?;
            let zone = ZoneResolver::new(zf)?;
            let ns = IterativeNameserver::primary(vec![zone]);
            Base::new(ns)
                .with_adapter(TransportMedium::Udp, UdpAdapter::default())
                .deploy()
                .await
        });

        // Clients
        sim.node_require_join("192.168.2.101", || async {
            set_dns_resolver(resolve)?;

            let result = lookup_host(("www.subdomain.example.org.", 80)).await;
            tracing::info!("{}", result.is_err());

            if let Err(e) = result {
                assert_eq!(
                    e.downcast::<Error>().unwrap(),
                    Error::new(ResponseCode::NxDomain, "")
                )
            } else {
                panic!("there must be an error");
            }

            Ok(())
        });
        sim.node("192.168.2.102", || async { Ok(()) });

        let _ = sim.run();
    }
}

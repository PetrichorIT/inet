use des::{globals, prelude::*, random, time::sleep};
use inet::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    ipv4::{arp::arpa, socket::RawV4Socket},
    utils::SimpleSim,
};
use serial_test::serial;
use types::ip::Ipv4Packet;

#[test]
#[serial]
fn v4() -> Result<(), des::Failure> {
    // des::tracing::init();

    let mut sim = SimpleSim::default();
    sim.inner_mut().include_cfg(include_str!("arp/v4.par.yml"));

    for i in 0..5 {
        sim.raw(&format!("node[{i}]"), |mut rx| async move {
            let ip = current().prop::<Ipv4Addr>("addr").unwrap().get().unwrap();
            ioctx()
                .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ipv4(ip))
                .unwrap();

            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    if msg.body.is::<Ipv4Packet>() {
                        let msg = msg.body.content::<Ipv4Packet>();
                        assert_eq!(msg.dst, ip);
                        tracing::info!("received message from {}", msg.src);
                    }
                }
            });

            let mut valid_addrs = Vec::new();
            for i in 0..5 {
                let ip = globals()
                    .get(&format!("node[{i}]"))
                    .unwrap()
                    .prop::<Ipv4Addr>("addr")
                    .unwrap()
                    .get()
                    .unwrap();
                valid_addrs.push(ip)
            }

            let mut sock = RawV4Socket::new(0).unwrap();
            let mut index = random::<u64>() as usize % 5;
            while SimTime::now() < 5.0.into() {
                sleep(Duration::from_secs_f64(random())).await;

                let target = valid_addrs[index];
                index = (index + 1) % 5;
                if target == ip {
                    continue;
                }

                tracing::info!("sending packet to {}", target);
                sock.bind(ip).unwrap();
                sock.try_send_to(&[42, 42], target).unwrap();
            }

            let arpa = arpa()?;
            assert_eq!(arpa.len(), 6);

            Ok(())
        });
    }

    sim.run_max_time(10.0).map(|_| ())
}

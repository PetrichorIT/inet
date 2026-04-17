use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use des::{prelude::*, time::sleep};
use des_ndl::{Ndl, registry};
use inet::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    tcp::{TcpListener, TcpStream},
};
use tokio::spawn;

#[derive(Default)]
struct OneAttemptClient {
    done: Arc<AtomicBool>,
}

impl Module for OneAttemptClient {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 200).into()),
            )
            .unwrap();

        let done = self.done.clone();
        spawn(async move {
            let sock = TcpStream::connect("69.0.0.69:8000").await;
            tracing::info!("{:?}", sock);
            assert!(sock.is_err());
            done.store(true, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) -> Result<(), des::Error> {
        assert!(self.done.load(Ordering::SeqCst));
        Ok(())
    }
}

#[derive(Default)]
struct MultipleAttemptClient<const EXPECT: bool> {
    done: Arc<AtomicBool>,
}

impl<const EXPECT: bool> Module for MultipleAttemptClient<EXPECT> {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 100).into()),
            )
            .unwrap();

        let done = self.done.clone();
        spawn(async move {
            let addrs: [SocketAddr; 3] = [
                "69.0.0.69:8000".parse().unwrap(),
                "69.0.0.69:9000".parse().unwrap(),
                "69.0.0.69:10000".parse().unwrap(),
            ];
            let sock = TcpStream::connect(&addrs[..]).await;
            tracing::info!("{:?}", sock);
            assert_eq!(sock.is_ok(), EXPECT);
            done.store(true, Ordering::SeqCst);
        });
    }

    fn at_sim_end(&mut self) -> Result<(), des::Error> {
        assert!(self.done.load(Ordering::SeqCst));
        Ok(())
    }
}

#[derive(Default)]
struct EmptyServer {}

impl Module for EmptyServer {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 69).into()),
            )
            .unwrap();
    }
}

#[derive(Default)]
struct BoundServer {}

impl Module for BoundServer {
    fn at_sim_start(&mut self, _: usize) {
        ioctx()
            .add_interface(
                InterfaceDef::new("en0", NetworkDevice::eth())
                    .ip(Ipv4Addr::new(69, 0, 0, 69).into()),
            )
            .unwrap();

        spawn(async move {
            let sock = TcpListener::bind("0.0.0.0:10000").await.unwrap();
            loop {
                let (stream, _) = sock.accept().await.unwrap();
                sleep(Duration::from_secs(1)).await;
                drop(stream);
            }
        });
    }
}

#[test]
#[serial_test::serial]
fn tcp_rst_for_closed_port() -> Result<(), Box<dyn std::error::Error>> {
    type Server = EmptyServer;
    type Client = OneAttemptClient;

    let mut sim = Sim::new(()).with_stack(inet::init);
    let def = serde_norway::from_str(include_str!("tcp2.yml"))?;
    sim.node("", Ndl::new(&mut registry![Client, Server, else _], &def)?)?;

    let rt = sim.seeded(233).build();

    rt.run().into_result().map(|_| ())?;
    Ok(())
}

#[test]
#[serial_test::serial]
fn tcp_rst_on_multiple_tries() -> Result<(), Box<dyn std::error::Error>> {
    type Server = EmptyServer;
    type Client = MultipleAttemptClient<false>;

    let mut sim = Sim::new(()).with_stack(inet::init);
    let def = serde_norway::from_str(include_str!("tcp2.yml"))?;
    sim.node("", Ndl::new(&mut registry![Client, Server, else _], &def)?)?;

    let rt = sim.seeded(233).build();

    rt.run().into_result().map(|_| ())?;
    Ok(())
}

#[test]
#[serial_test::serial]
fn tcp_rst_on_multiple_tries_with_success() -> Result<(), Box<dyn std::error::Error>> {
    type Server = BoundServer;
    type Client = MultipleAttemptClient<true>;

    let mut sim = Sim::new(()).with_stack(inet::init);
    let def = serde_norway::from_str(include_str!("tcp2.yml"))?;
    sim.node("", Ndl::new(&mut registry![Client, Server, else _], &def)?)?;

    let rt = sim.seeded(233).build();

    rt.run().into_result().map(|_| ())?;
    Ok(())
}

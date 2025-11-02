use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use des::{net::globals, prelude::*, registry, time::sleep};
use inet::{
    interface::{InterfaceDef, NetworkDevice},
    ioctx,
    tcp::{TcpListener, TcpStream},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use types::ip::Ipv4Packet;

#[derive(Default)]
struct Node {
    done: Arc<AtomicUsize>,
}

impl Module for Node {
    fn at_sim_start(&mut self, s: usize) {
        if s == 0 {
            // add_plugin(TcpDebugPlugin, 0);
            return;
        }

        dbg!(current().props_keys());

        let ip = current().prop::<IpAddr>("addr").unwrap().get().unwrap();
        ioctx()
            .add_interface(InterfaceDef::new("en0", NetworkDevice::eth()).ip(ip))
            .unwrap();

        let target = current()
            .prop::<Vec<u8>>("targets")
            .unwrap()
            .or_default()
            .get();
        let targets = target
            .into_iter()
            .map(|v| Ipv4Addr::new(100, 0, 0, v + 100))
            .collect::<Vec<_>>();

        let expected: usize = current()
            .prop::<usize>("expected")
            .unwrap()
            .or_default()
            .get();

        let done = self.done.clone();
        tokio::spawn(async move {
            for target in targets {
                sleep(Duration::from_secs_f64(random())).await;
                let buf = [42; 42];
                tracing::info!("sending 42 bytes to {target}");
                TcpStream::connect(SocketAddrV4::new(target, 100))
                    .await
                    .unwrap()
                    .write(&buf)
                    .await
                    .unwrap();
            }
            done.fetch_add(1, Ordering::SeqCst);
        });

        let done = self.done.clone();
        tokio::spawn(async move {
            if expected == 0 {
                return;
            }

            let lis = TcpListener::bind("0.0.0.0:100").await.unwrap();
            for _ in 0..expected {
                let (mut stream, from) = lis.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                tracing::info!("recieved {n} bytes from {}", from.ip());
            }
            done.fetch_add(1, Ordering::SeqCst);
        });
    }

    fn num_sim_start_stages(&self) -> usize {
        2
    }

    fn at_sim_end(&mut self) -> Result<(), RuntimeError> {
        assert_eq!(self.done.load(Ordering::SeqCst), 2);
        Ok(())
    }

    fn handle_message(&mut self, msg: Message) {
        panic!(
            "msg :: {} :: {} // {:?} -> {:?}",
            msg,
            current().name(),
            msg.body.content::<Ipv4Packet>().src,
            msg.body.content::<Ipv4Packet>().dst
        )
    }
}

type Switch = inet::utils::LinkLayerSwitch;

#[derive(Default)]
struct Main;
impl Module for Main {
    fn at_sim_start(&mut self, _stage: usize) {
        let mut targets = Vec::new();
        for i in 0..5 {
            let s = globals()
                .get(&format!("node[{i}]").into())
                .expect("no node found")
                .prop::<Vec<u8>>("targets")
                .expect("no prop found")
                .get()
                .unwrap();
            targets.extend(s)
        }

        for i in 0..5 {
            let c = targets.iter().filter(|e| **e == i).count();
            globals()
                .get(&format!("node[{i}]").into())
                .unwrap()
                .prop::<usize>("expected")
                .unwrap()
                .set(c);
        }
    }
}

#[test]
fn tcp_lan_v4() -> Result<(), RuntimeError> {
    des::tracing::init();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_cfg(include_str!("tcp-lan/v4.par.yml"))
        .with_ndl("tests/tcp-lan/main.yml", registry![Node, Switch, Main])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).build(app.freeze());
    rt.run().map(|_| ())
}

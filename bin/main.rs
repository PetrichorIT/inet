use des::{
    net::module::{set_setup_fn, ModuleContext},
    prelude::*,
};
use inet::inet::{IOContext, IOPlugin, UdpSocket};

#[NdlModule("bin")]
struct A {}
#[async_trait::async_trait]
impl AsyncModule for A {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        IOContext::eth_default(Ipv4Addr::new(100, 100, 100, 100)).set();
        tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:2000").await.unwrap();
            loop {
                let mut buf = [0u8; 512];
                let (n, src) = sock.recv_from(&mut buf).await.unwrap();
                log::info!("Received {} bytes from {}", n, src);
                sock.send_to(&buf[..n], src).await.unwrap();
            }
        });
    }

    async fn handle_message(&mut self, _: Message) {
        panic!()
    }
}

#[NdlModule("bin")]
struct B {}
#[async_trait::async_trait]
impl AsyncModule for B {
    fn new() -> Self {
        Self {}
    }

    async fn at_sim_start(&mut self, _: usize) {
        IOContext::eth_default(Ipv4Addr::new(200, 200, 200, 200)).set();
        tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:1000").await.unwrap();
            sock.connect("100.100.100.100:2000").await.unwrap();

            sock.send(&vec![42u8; 100]).await.unwrap();

            let mut buf = [0u8; 512];
            let n = sock.recv(&mut buf).await.unwrap();
            println!("{:?}", &buf[..n])
        });
    }

    async fn handle_message(&mut self, _: Message) {
        panic!()
    }
}

#[NdlSubsystem("bin")]
struct Main {}

fn inet_setup_fn(this: &ModuleContext) {
    this.add_plugin(IOPlugin::new(), 100, false);
}

fn main() {
    ScopedLogger::new().finish().unwrap();
    set_setup_fn(inet_setup_fn);

    let app = Main {}.build_rt();
    let rt = Runtime::new_with(app, RuntimeOptions::seeded(123));
    let _ = rt.run();
}

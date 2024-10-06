use axum::{extract::Path, response::Response, routing::get, Router};
use connector::InetTcpStream;
use des::{prelude::*, registry};
use hyper::{
    client,
    server::{self, accept::from_stream},
    service::make_service_fn,
    Body, Request, Uri,
};
use inet::{
    interface::{add_interface, Interface, NetworkDevice},
    TcpListener,
};
use inet_pcap::pcap;
use std::{convert::Infallible, fs::File};
use tokio::spawn;

#[derive(Default)]
struct Client;

impl Module for Client {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::eth(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 2, 101).into(),
        ))
        .unwrap();

        pcap(File::create("results/client.pcap").unwrap()).unwrap();

        spawn(async move {
            let client = client::Client::builder().build(connector::connector());

            let mut request = Request::new(Body::empty());
            *request.uri_mut() = Uri::from_static("http://192.168.2.10:80/greet/foo");
            let res = client.request(request).await.unwrap();

            let (parts, body) = res.into_parts();
            let body = hyper::body::to_bytes(body).await.unwrap();
            let res = Response::from_parts(parts, body);

            tracing::info!("got response {:?}", res);
        });
    }
}

#[derive(Default)]
struct Server;

impl Module for Server {
    fn at_sim_start(&mut self, _: usize) {
        add_interface(Interface::eth(
            NetworkDevice::eth(),
            Ipv4Addr::new(192, 168, 2, 10).into(),
        ))
        .unwrap();

        spawn(async move {
            let router = Router::new().route(
                "/greet/:name",
                get(|Path(name): Path<String>| async move { format!("Hello {name}!") }),
            );

            let lis = TcpListener::bind("0.0.0.0:80").await.unwrap();
            let accept = from_stream(async_stream::stream! {
                loop {
                    yield lis.accept().await.map(|(s, _)| InetTcpStream(s));
                }
            });

            server::Server::builder(accept)
                .serve(make_service_fn(move |_| {
                    let router = router.clone();
                    async move { Ok::<_, Infallible>(router) }
                }))
                .await
                .unwrap();
        });
    }
}

mod connector {
    use std::future::Future;
    use std::pin::Pin;

    use hyper::client::connect::{Connected, Connection};
    use hyper::Uri;
    use tokio::io::AsyncRead;
    use tokio::io::AsyncWrite;
    use tower::Service;

    type Fut = Pin<Box<dyn Future<Output = Result<InetTcpStream, std::io::Error>> + Send>>;

    pub fn connector(
    ) -> impl Service<Uri, Response = InetTcpStream, Error = std::io::Error, Future = Fut> + Clone
    {
        tower::service_fn(|uri: Uri| {
            Box::pin(async move {
                let conn = inet::TcpStream::connect(uri.authority().unwrap().as_str()).await?;
                Ok::<_, std::io::Error>(InetTcpStream(conn))
            }) as Fut
        })
    }

    pub struct InetTcpStream(pub inet::TcpStream);
    impl AsyncRead for InetTcpStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for InetTcpStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl Connection for InetTcpStream {
        fn connected(&self) -> hyper::client::connect::Connected {
            Connected::new()
        }
    }
}

fn main() {
    des::tracing::init();

    let app = Sim::new(())
        .with_stack(inet::init)
        .with_ndl("main.yml", registry![Client, Server, else _])
        .map_err(|e| println!("{e}"))
        .unwrap();
    let rt = Builder::seeded(123).max_time(50.0.into()).build(app);
    let _ = rt.run();
}

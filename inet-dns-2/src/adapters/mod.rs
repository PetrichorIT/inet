mod tcp;
mod udp;

pub use tcp::TcpBased;
pub use udp::UdpBased;

pub const DEFAULT_PORT: u16 = 53;

#[cfg(test)]
mod tests {
    use inet::{test_util::SimpleSim, TcpListener, UdpSocket};

    use super::*;

    #[test]
    #[serial_test::serial]
    fn test_default_port() {
        let mut sim = SimpleSim::new(inet::init);
        sim.node("192.168.2.101", || async move {
            let udp = UdpSocket::bind("0.0.0.0:53").await?;
            let tcp = TcpListener::bind("0.0.0.0:53").await?;

            Ok(())
        });
        let _ = sim.run();
    }
}

use std::io::ErrorKind;

use des::runtime::RuntimeError;
use serial_test::serial;

use crate::{UdpSocket, utils::SimpleSim};

#[test]
#[serial]
fn send_failure_ip_missmatch() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.node("192.168.2.1", || async move {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let err = sock
            .send_to(&[1, 2, 3], "[2003:a:b::1]:80")
            .await
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "ip version missmatch");

        let err = sock.send_to(&[1, 2, 3], "0.0.0.0:80").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "unspecified destination");

        Ok(())
    });

    sim.run()
}

use std::time::Duration;

use serial_test::serial;

use crate::{
    socket::{AsRawFd, bsd_socket_info},
    tcp::{Config, TcpSocket},
    utils::SimpleSim,
};

#[test]
#[serial]
fn create_socket_v4_host() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let v4 = TcpSocket::new_v4()?;
        let v6 = TcpSocket::new_v6()?;

        let _v4 = v4.bind("0.0.0.0:80".parse().unwrap())?;
        let error = v6.bind("[::]:81".parse().unwrap()).unwrap_err();
        assert_eq!(error.to_string(), "address not available");

        Ok(())
    });
    sim.run()
}

#[test]
#[serial]
fn create_socket_v6_host() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("2003:a:1::1", || async move {
        let v4 = TcpSocket::new_v4()?;
        let v6 = TcpSocket::new_v6()?;

        let error = v4.bind("0.0.0.0:80".parse().unwrap()).unwrap_err();
        let _v6 = v6.bind("[::]:81".parse().unwrap())?;
        assert_eq!(error.to_string(), "address not available");

        Ok(())
    });
    sim.run()
}

#[test]
#[serial]
fn socketopt() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let v4 = TcpSocket::new_v4()?;
        let default = Config::default();

        assert_eq!(v4.maximum_segement_size()?, default.mss.unwrap_or(0));
        v4.set_maximum_segement_size(800)?;
        assert_eq!(v4.maximum_segement_size()?, 800);

        assert_eq!(v4.inital_seq_no()?, default.iss.unwrap_or(0));
        v4.set_inital_seq_no(42)?;
        assert_eq!(v4.inital_seq_no()?, 42);

        assert_eq!(v4.reuseaddr()?, default.reuseaddr);
        v4.set_reuseaddr(true)?;
        assert_eq!(v4.reuseaddr()?, true);

        assert_eq!(v4.reuseport()?, default.reuseport);
        v4.set_reuseport(true)?;
        assert_eq!(v4.reuseport()?, true);

        assert_eq!(v4.send_buffer_size()?, default.send_buffer_cap);
        v4.set_send_buffer_size(800)?;
        assert_eq!(v4.send_buffer_size()?, 800);

        assert_eq!(v4.recv_buffer_size()?, default.recv_buffer_cap);
        v4.set_recv_buffer_size(800)?;
        assert_eq!(v4.recv_buffer_size()?, 800);

        assert_eq!(v4.linger()?, default.linger);
        v4.set_linger(Some(Duration::from_secs(1)))?;
        assert_eq!(v4.linger()?, Some(Duration::from_secs(1)));

        Ok(())
    });
    sim.run()
}

#[test]
#[serial]
fn close_unconverted_socket() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let v4 = TcpSocket::new_v4()?;
        let fd = v4.as_raw_fd();
        assert!(bsd_socket_info(fd).is_ok());
        drop(v4);
        assert!(bsd_socket_info(fd).is_err());

        Ok(())
    });
    sim.run()
}

#[test]
#[serial]
fn bind_wrong_addr_fam() -> Result<(), des::Failure> {
    let mut sim = SimpleSim::default();
    sim.node_require_join("192.168.2.101", || async move {
        let v4 = TcpSocket::new_v4()?;
        let error = v4.bind("[::]:80".parse().unwrap()).unwrap_err();
        assert_eq!(error.to_string(), "invalid address family");
        Ok(())
    });

    sim.node_require_join("2003:a:1::b", || async move {
        let v4 = TcpSocket::new_v6()?;
        let error = v4.bind("0.0.0.0:80".parse().unwrap()).unwrap_err();
        assert_eq!(error.to_string(), "invalid address family");
        Ok(())
    });
    sim.run()
}

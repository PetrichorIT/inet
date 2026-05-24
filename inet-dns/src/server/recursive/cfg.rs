use std::net::IpAddr;

#[derive(Debug, Default)]
pub struct Config {
    pub roots: Vec<(IpAddr, String)>,
}

use std::{
    fmt::Debug,
    hash::{DefaultHasher, Hash, Hasher},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
    u32,
};

use crate::tcp2::Quad;
use des::time::SimTime;

#[derive(Clone)]
pub struct Config {
    pub enable_congestion_control: bool,
    pub enable_reorder_buffer: bool,
    pub enable_sack: bool,

    pub dup_ack_resend_cnt: Option<usize>,

    pub send_buffer_cap: usize,
    pub recv_buffer_cap: usize,
    pub syn_resent_count: usize,
    pub initial_rto: Duration,
    pub mss: Option<u16>,
    pub iss: Option<u32>,
    pub ttl: u8,
    pub linger: Option<Duration>,
    pub reuseport: bool,
    pub reuseaddr: bool,
    pub rst_for_syn: bool,
    pub clock: Arc<dyn Fn() -> SimTime>,
}

impl Config {
    pub fn test_default() -> Config {
        Config {
            enable_congestion_control: false,
            enable_reorder_buffer: true,
            enable_sack: false,

            // TODO: change to Some(3) breaking no tests
            dup_ack_resend_cnt: Some(3),

            send_buffer_cap: 4096,
            recv_buffer_cap: 4096,
            syn_resent_count: 3,
            initial_rto: Duration::from_secs(10),
            mss: None,
            iss: Some(0), // TODO: This is a debug setting to prevent random ISS
            linger: None,
            ttl: 64,
            reuseaddr: false,
            reuseport: false,
            rst_for_syn: true,
            clock: Arc::new(SimTime::now),
        }
    }

    pub fn for_listener(&self, _addr: SocketAddr) -> Config {
        Config { ..self.clone() }
    }

    pub fn iss_for(&self, quad: &Quad, secret: &[u8]) -> u32 {
        self.iss.unwrap_or_else(|| {
            // RFC 9293
            // -> 3.4.1. Initial Sequence Number Selection
            // A TCP implementation MUST use the above type of "clock" for clock-driven selection of initial
            // sequence numbers (MUST-8), and SHOULD generate its initial sequence numbers with the expression:
            //
            // ISN = M + F(localip, localport, remoteip, remoteport, secretkey)

            let m = ((self.clock)().as_millis() % u32::MAX as u128) as u32;

            let mut hasher = DefaultHasher::new();
            quad.hash(&mut hasher);
            secret.hash(&mut hasher);

            m + hasher.finish() as u32
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_congestion_control: false,
            enable_reorder_buffer: true,
            enable_sack: false,

            dup_ack_resend_cnt: Some(3),

            send_buffer_cap: 4096,
            recv_buffer_cap: 4096,
            initial_rto: Duration::from_secs(3),
            syn_resent_count: 3,
            mss: None,
            iss: Some(0), // TODO: This is a debug setting to prevent random ISS
            linger: None,
            ttl: 64,
            reuseaddr: false,
            reuseport: false,
            rst_for_syn: true,
            clock: Arc::new(SimTime::now),
        }
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("enable_congestion_control", &self.enable_congestion_control)
            .field("enable_reorder_buffer", &self.enable_reorder_buffer)
            .field("enable_sack", &self.enable_sack)
            .field("send_buffer_cap", &self.send_buffer_cap)
            .field("recv_buffer_cap", &self.recv_buffer_cap)
            .field("syn_resent_count", &self.syn_resent_count)
            .field("initial_rto", &self.initial_rto)
            .field("mss", &self.mss)
            .field("iss", &self.iss)
            .field("ttl", &self.ttl)
            .field("linger", &self.linger)
            .field("reuseport", &self.reuseport)
            .field("reuseaddr", &self.reuseaddr)
            .field("rst_for_syn", &self.rst_for_syn)
            .finish()
    }
}

unsafe impl Send for Config {}

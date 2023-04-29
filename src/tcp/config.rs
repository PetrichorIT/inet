use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpConfig {
    pub rst_on_syn: bool,
    pub nack: bool,

    pub rx_buffer_size: usize,
    pub tx_buffer_size: usize,

    pub mss: usize,

    pub ttl: u8,
    pub timeout: Duration,
    pub timewait: Duration,
    pub syn_sent_thresh: usize,
    pub cong_max_thresh: usize,

    pub linger: Option<Duration>,
    pub nodelay: bool,

    pub reuseport: bool,
    pub reuseaddr: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            rst_on_syn: true,
            nack: false,

            rx_buffer_size: 4096,
            tx_buffer_size: 4096,

            mss: 1024,

            ttl: 20,
            timeout: Duration::from_secs(1),
            timewait: Duration::from_secs(1),
            syn_sent_thresh: 3,
            cong_max_thresh: 32768,

            linger: None,
            nodelay: true,
            reuseaddr: true,
            reuseport: true,
        }
    }
}

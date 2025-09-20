use types::tcp::TcpPacket;

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```text
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
pub struct RecvSequenceSpace {
    /// receive next
    pub nxt: u32,
    /// receive window <= wnd_max
    pub wnd: u16,
    /// the maximum allowed value, as determined by cong control.
    pub wnd_max: u16,
    /// receive urgent pointer
    pub up: u32,
    /// initial receive sequence number
    pub irs: u32,
}

impl RecvSequenceSpace {
    pub fn from_syn(pkt: &TcpPacket, wnd: u16, wnd_max: u16) -> Self {
        Self {
            irs: pkt.seq_no,
            nxt: pkt.seq_no.wrapping_add(1),
            wnd,
            wnd_max,
            up: pkt.seq_no,
        }
    }

    pub const fn empty(wnd: u16, wnd_max: u16) -> Self {
        Self {
            nxt: 0,
            wnd,
            wnd_max,
            irs: 0,
            up: 0,
        }
    }
}

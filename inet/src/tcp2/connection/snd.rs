use crate::tcp2::Quad;

use super::Config;

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```text
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
pub struct SendSequenceSpace {
    /// send unacknowledged
    pub una: u32,
    /// send next
    pub nxt: u32,
    /// send window
    pub wnd: u16,
    /// send urgent pointer
    pub up: bool,
    /// segment sequence number used for last window update
    pub wl1: u32,
    /// segment acknowledgment number used for last window update
    pub wl2: u32,
    /// initial send sequence number
    pub iss: u32,
    /// maximum segment size
    pub mss: u16,

    pub syn_resend_counter: usize,

    pub closed: bool,
    pub closed_at: Option<u32>,

    pub c: CongestionControl,
}

impl SendSequenceSpace {
    pub fn new(quad: &Quad, cfg: &Config) -> Self {
        let iss = cfg.iss_for(&quad, &[]);
        let mss = cfg.mss.unwrap_or(if quad.is_ipv4() { 536 } else { 1220 });
        Self {
            iss,
            una: iss,
            nxt: iss,
            wnd: cfg.send_buffer_cap as u16,
            up: false,
            wl1: 0,
            wl2: 0,
            mss,

            syn_resend_counter: 0,

            closed: false,
            closed_at: None,

            c: CongestionControl::new(cfg.enable_congestion_control, mss),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CongestionControl {
    // Congestion control variables
    pub enabled: bool,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub avoid_counter: u32,
    pub slow_start: bool,
    pub dup_ack_counter: usize,
}

impl CongestionControl {
    pub fn new(enabled: bool, mss: u16) -> Self {
        Self {
            enabled,
            cwnd: mss as u32,
            ssthresh: 4 * (mss as u32),
            avoid_counter: 0,
            slow_start: enabled,
            dup_ack_counter: 0,
        }
    }
}

impl SendSequenceSpace {
    pub fn on_ack(&mut self, n: u32) {
        if self.c.enabled {
            if self.c.cwnd < self.c.ssthresh {
                // Slow start
                self.c.cwnd += self.mss as u32;
                self.c.avoid_counter = self.c.cwnd;

                // ctrl.debug_cong_window
                //     .collect(ctrl.congestion_window as f64);
            } else {
                // AIMD
                self.c.avoid_counter = self.c.avoid_counter.saturating_sub(n);
                if self.c.avoid_counter == 0 {
                    self.c.cwnd += self.mss as u32;
                    // FIXME: custom addition may be a bad idea but we self see.
                    self.c.cwnd = self.c.cwnd.min(self.wnd as u32);
                    self.c.avoid_counter = self.c.cwnd;
                }

                // ctrl.debug_cong_window
                //     .collect(ctrl.congestion_window as f64);
            }
        }
    }

    pub fn on_dup_ack(&mut self) {
        self.c.cwnd = self.c.cwnd / 2;
        self.c.dup_ack_counter = 0;
    }

    pub fn on_timeout(&mut self) {
        // TCP RENO
        self.c.cwnd = (self.c.cwnd / 2).max(self.mss as u32);
        self.c.ssthresh = self.c.cwnd;
    }

    pub fn num_unacked_bytes(&self) -> u32 {
        self.closed_at.unwrap_or(self.nxt).wrapping_sub(self.una)
    }

    pub fn remaining_window_space(&self) -> u32 {
        if self.c.enabled {
            (self.wnd as u32 - self.num_unacked_bytes())
                .min(self.c.cwnd.saturating_sub(self.num_unacked_bytes()))
        } else {
            self.wnd as u32 - self.num_unacked_bytes()
        }
    }
}

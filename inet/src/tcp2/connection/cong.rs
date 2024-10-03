use super::Connection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CongestionControl {
    // Always present
    pub mss: u16,

    // Congestion control variables
    pub enabled: bool,
    pub wnd: u32,
    pub ssthresh: u32,
    pub avoid_counter: u32,
    pub slow_start: bool,
    pub dup_ack_counter: usize,
}

impl CongestionControl {
    pub fn new(enabled: bool, mss: u16) -> Self {
        if enabled {
            Self::enabled(mss)
        } else {
            Self::disabled(mss)
        }
    }

    pub fn enabled(mss: u16) -> Self {
        Self {
            mss,
            enabled: true,
            wnd: mss as u32,
            ssthresh: 4 * (mss as u32),
            avoid_counter: 0,
            slow_start: true,
            dup_ack_counter: 0,
        }
    }

    pub fn disabled(mss: u16) -> Self {
        Self {
            mss,
            enabled: false,
            wnd: 0,
            ssthresh: 0,
            avoid_counter: 0,
            slow_start: false,
            dup_ack_counter: 0,
        }
    }

    pub fn on_ack(&mut self, n: u32, send_wnd: u32) {
        if self.enabled {
            if self.wnd < self.ssthresh {
                // Slow start
                self.wnd += self.mss as u32;
                self.avoid_counter = self.wnd;

                // ctrl.debug_cong_window
                //     .collect(ctrl.congestion_window as f64);
            } else {
                // AIMD
                self.avoid_counter = self.avoid_counter.saturating_sub(n);
                if self.avoid_counter == 0 {
                    self.wnd += self.mss as u32;
                    // FIXME: custom addition may be a bad idea but we self see.
                    self.wnd = self.wnd.min(send_wnd);
                    self.avoid_counter = self.wnd;
                }

                // ctrl.debug_cong_window
                //     .collect(ctrl.congestion_window as f64);
            }
        }
    }

    pub fn on_dup_ack(&mut self) {
        self.wnd = self.wnd / 2;
        self.dup_ack_counter = 0;
    }

    pub fn on_timeout(&mut self) {
        // TCP Reno
        self.wnd = (self.wnd / 2).max(self.mss as u32);
        self.ssthresh = self.wnd;
    }
}

impl Connection {
    pub fn remaining_window_space(&self) -> u32 {
        if self.cong.enabled {
            (self.send.wnd as u32 - self.num_unacked_bytes())
                .min(self.cong.wnd.saturating_sub(self.num_unacked_bytes()))
        } else {
            self.send.wnd as u32 - self.num_unacked_bytes()
        }
    }
}

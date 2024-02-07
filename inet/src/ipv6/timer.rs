use std::net::Ipv6Addr;

use des::{
    net::message::{schedule_at, Message},
    time::SimTime,
};

use crate::interface::{IfId, ID_IPV6_TIMEOUT, KIND_IO_TIMEOUT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerToken {
    NeighborSolicitationRetransmitTimeout { target: Ipv6Addr, ifid: IfId },
}

pub struct TimerCtrl {
    timers: Vec<(TimerToken, SimTime)>,
    wakeups: Vec<SimTime>,
}

impl TimerCtrl {
    pub fn new() -> Self {
        Self {
            timers: Vec::new(),
            wakeups: Vec::with_capacity(2),
        }
    }

    pub fn schedule(&mut self, token: TimerToken, timeout: SimTime) {
        self.timers.push((token, timeout));
        self.timers.sort_by(|l, r| l.1.cmp(&r.1));
    }

    pub fn active(&self, token: TimerToken) -> bool {
        self.timers.iter().any(|t| t.0 == token)
    }

    pub fn cancel(&mut self, token: TimerToken) {
        self.timers.retain(|e| e.0 != token)
    }

    pub fn next(&self) -> Option<SimTime> {
        self.timers.iter().next().map(|v| v.1)
    }

    pub fn schedule_wakeup(&mut self) {
        let Some(next) = self.next() else {
            return;
        };

        if let Some(wakeup) = self.wakeups.first() {
            if *wakeup < next {
                return;
            }
        }

        self.wakeups.push(next);
        self.wakeups.sort();

        let msg = Message::new()
            .kind(KIND_IO_TIMEOUT)
            .id(ID_IPV6_TIMEOUT)
            .build();
        schedule_at(msg, next);
    }

    pub fn recv(&mut self, _msg: &Message) -> Vec<TimerToken> {
        let mut tokens = Vec::new();
        let now = SimTime::now();
        while let Some(f) = self.wakeups.first() {
            if *f <= now {
                self.wakeups.pop();
            } else {
                break;
            }
        }

        while let Some(entry) = self.timers.first() {
            if entry.1 <= now {
                tokens.push(entry.0);
                self.timers.pop();
            } else {
                break;
            }
        }

        tokens
    }
}

use std::net::Ipv6Addr;

use des::{
    net::message::{schedule_at, Message},
    time::SimTime,
};
use inet_types::ip::Ipv6Prefix;

use crate::interface::{IfId, ID_IPV6_TIMEOUT, KIND_IO_TIMEOUT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimerToken {
    PrefixTimeout {
        ifid: IfId,
        prefix: Ipv6Prefix,
    },
    RouterAdvertismentUnsolicited {
        ifid: IfId,
    },
    RouterAdvertismentSolicited {
        ifid: IfId,
        dst: Ipv6Addr,
    },
    NeighborSolicitationRetransmitTimeout {
        target: Ipv6Addr,
        ifid: IfId,
    },
    DelayedJoinMulticast {
        ifid: IfId,
        multicast: Ipv6Addr,
    },
    MulticastListenerDiscoverySendReport {
        ifid: IfId,
        multicast_addr: Ipv6Addr,
    },
}

#[derive(Debug)]
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
        assert!(
            timeout >= SimTime::now(),
            "cannot assign timer to the past: current={} requested_timer={timeout} token={token:?}",
            SimTime::now()
        );

        self.timers.push((token, timeout));
        self.timers.sort_by(|l, r| l.1.cmp(&r.1));
    }

    pub fn reschedule(&mut self, token: &TimerToken, timeout: SimTime) {
        assert!(
            timeout >= SimTime::now(),
            "cannot reassign timer to the past: current={} requested_timer={timeout} token={token:?}",
            SimTime::now()
        );
        let Some((i, _)) = self
            .timers
            .iter()
            .enumerate()
            .find(|(_, (v, _))| v == token)
        else {
            self.schedule(token.clone(), timeout);
            return;
        };

        let (token, _) = self.timers.remove(i);
        self.schedule(token, timeout);
    }

    pub fn active(&self, token: &TimerToken) -> Option<SimTime> {
        self.timers
            .iter()
            .find(|t| t.0 == *token)
            .map(|(_, deadline)| *deadline)
    }

    pub fn cancel(&mut self, token: &TimerToken) {
        self.timers.retain(|e| e.0 != *token)
    }

    pub fn next(&self) -> Option<SimTime> {
        self.timers.iter().next().map(|v| v.1)
    }

    pub fn schedule_wakeup(&mut self) {
        while let Some(first) = self.timers.first() {
            if first.1 < SimTime::now() {
                tracing::error!(
                    timer=?first, "timer expired without wakeup"
                );
                self.timers.remove(0);
            } else {
                break;
            }
        }

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
                tokens.push(self.timers.remove(0).0);
            } else {
                break;
            }
        }
        tokens
    }
}

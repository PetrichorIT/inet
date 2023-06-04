use std::{fmt::Debug, time::Duration};

use des::time::{sleep_until, SimTime};

pub(super) struct Timers {
    pub(super) cfg: TimersCfg,
    hold_timer: SimTime,
    keepalive_timer: SimTime,
    delay_open_timer: SimTime,
    connection_retry_timer: SimTime,
}

#[derive(Debug)]
pub(super) struct TimersCfg {
    pub(super) hold_time: Duration,
    pub(super) keepalive_time: Duration,
    pub(super) delay_open_time: Duration,
    pub(super) connection_retry_time: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Timer {
    HoldTimer,
    KeepaliveTimer,
    DelayOpenTimer,
    ConnectionRetryTimer,
}

impl Timers {
    pub fn new(cfg: TimersCfg) -> Self {
        Timers {
            cfg,
            hold_timer: SimTime::MAX,
            keepalive_timer: SimTime::MAX,
            delay_open_timer: SimTime::MAX,
            connection_retry_timer: SimTime::MAX,
        }
    }

    pub fn enable_timer(&mut self, timer: Timer) {
        use Timer::*;
        match timer {
            HoldTimer => self.hold_timer = SimTime::now() + self.cfg.hold_time,
            KeepaliveTimer => self.keepalive_timer = SimTime::now() + self.cfg.keepalive_time,
            DelayOpenTimer => self.delay_open_timer = SimTime::now() + self.cfg.delay_open_time,
            ConnectionRetryTimer => {
                self.connection_retry_timer = SimTime::now() + self.cfg.connection_retry_time
            }
        }
    }

    pub fn disable_timer(&mut self, timer: Timer) {
        use Timer::*;
        match timer {
            HoldTimer => self.hold_timer = SimTime::MAX,
            KeepaliveTimer => self.keepalive_timer = SimTime::MAX,
            DelayOpenTimer => self.delay_open_timer = SimTime::MAX,
            ConnectionRetryTimer => self.connection_retry_timer = SimTime::MAX,
        }
    }

    pub async fn next(&mut self) -> Timer {
        let mut min = (SimTime::MAX, Timer::HoldTimer);

        for (timer, kind) in [
            (&mut self.hold_timer, Timer::HoldTimer),
            (&mut self.keepalive_timer, Timer::KeepaliveTimer),
            (&mut self.delay_open_timer, Timer::DelayOpenTimer),
            (
                &mut self.connection_retry_timer,
                Timer::ConnectionRetryTimer,
            ),
        ] {
            if *timer <= SimTime::now() {
                // Timer expired
                continue;
            }

            if *timer < min.0 {
                min = (*timer, kind);
            }
        }

        if min.0 != SimTime::MAX {
            sleep_until(min.0).await;
            min.1
        } else {
            panic!("No timer set, but next() called, expected timer to be set")
        }
    }
}

impl Debug for Timers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let active = [
            (self.hold_timer, Timer::HoldTimer),
            (self.keepalive_timer, Timer::KeepaliveTimer),
            (self.delay_open_timer, Timer::DelayOpenTimer),
            (self.connection_retry_timer, Timer::ConnectionRetryTimer),
        ]
        .into_iter()
        .filter(|(deadline, _)| *deadline != SimTime::MAX)
        .collect::<Vec<_>>();

        f.debug_struct("Timers").field("active", &active).finish()
    }
}

impl Default for TimersCfg {
    fn default() -> Self {
        TimersCfg {
            hold_time: Duration::from_secs(180),
            keepalive_time: Duration::from_secs(60),
            delay_open_time: Duration::from_secs(30),
            connection_retry_time: Duration::from_secs(30),
        }
    }
}

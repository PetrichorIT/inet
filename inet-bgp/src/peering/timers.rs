use std::{fmt::Debug, time::Duration};

use des::time::{SimTime, sleep_until};

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
    Hold,
    Keepalive,
    DelayOpen,
    ConnectionRetry,
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
            Hold => self.hold_timer = SimTime::now() + self.cfg.hold_time,
            Keepalive => self.keepalive_timer = SimTime::now() + self.cfg.keepalive_time,
            DelayOpen => self.delay_open_timer = SimTime::now() + self.cfg.delay_open_time,
            ConnectionRetry => {
                self.connection_retry_timer = SimTime::now() + self.cfg.connection_retry_time
            }
        }
    }

    pub fn disable_timer(&mut self, timer: Timer) {
        use Timer::*;
        match timer {
            Hold => self.hold_timer = SimTime::MAX,
            Keepalive => self.keepalive_timer = SimTime::MAX,
            DelayOpen => self.delay_open_timer = SimTime::MAX,
            ConnectionRetry => self.connection_retry_timer = SimTime::MAX,
        }
    }

    pub async fn next(&mut self) -> Timer {
        let mut min = (SimTime::MAX, Timer::Hold);

        for (timer, kind) in [
            (&mut self.hold_timer, Timer::Hold),
            (&mut self.keepalive_timer, Timer::Keepalive),
            (&mut self.delay_open_timer, Timer::DelayOpen),
            (&mut self.connection_retry_timer, Timer::ConnectionRetry),
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
            (self.hold_timer, Timer::Hold),
            (self.keepalive_timer, Timer::Keepalive),
            (self.delay_open_timer, Timer::DelayOpen),
            (self.connection_retry_timer, Timer::ConnectionRetry),
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

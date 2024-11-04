use super::{is_between_wrapped, Config};
use des::time::SimTime;
use std::{collections::BTreeMap, time::Duration};

/// RFC 6298 - Computing TCP's Retransmission Timer
///
/// To compute the current RTO, a TCP sender maintains two state
/// variables, SRTT (smoothed round-trip time) and RTTVAR (round-trip
/// time variation).  In addition, we assume a clock granularity of G
/// seconds.
#[derive(Debug, Clone)]
pub struct Timers {
    pub send_times: BTreeMap<u32, SimTime>,
    pub rto: f64,
    pub running: Option<SmoothedRTT>,
}

#[derive(Debug, Clone)]
pub struct SmoothedRTT {
    pub srtt: f64,
    pub rttvar: f64,
    pub nto: usize,
}

impl Timers {
    pub fn new(cfg: &Config) -> Self {
        // (2.1) Until a round-trip time (RTT) measurement has been made for a
        // segment sent between the sender and receiver, the sender SHOULD
        // set RTO <- 1 second.
        Self {
            send_times: Default::default(),
            rto: cfg.initial_rto.as_secs_f64(),
            running: None,
        }
    }

    pub fn on_send(&mut self, seq: u32, now: SimTime) {
        self.send_times.insert(seq, now);
    }

    pub fn on_recv(&mut self, una: u32, ackn: u32, now: SimTime) {
        let mut meassurements = Vec::new();

        self.send_times.retain(|&seq, sent| {
            if is_between_wrapped(una, seq, ackn) {
                let elapsed = (now - *sent).as_secs_f64();
                meassurements.push(elapsed);
                false
            } else {
                true
            }
        });

        // TODO: ensure that the meassured segment was only sent once,
        // else the meassurement cannot know, whether the ack refers to the first
        // or second transmission
        meassurements
            .into_iter()
            .for_each(|m| self.on_meassurement(m));
    }

    pub fn on_meassurement(&mut self, r: f64) {
        // (4) ... Experience has shown that finer clock granularities (<= 100 msec)
        // perform somewhat better than coarser granularities.

        const G: f64 = 0.05;

        if let Some(ref mut comp) = self.running {
            // (2.3) When a subsequent RTT measurement R' is made, a host MUST set
            //      RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
            //      SRTT <- (1 - alpha) * SRTT + alpha * R'
            // The above SHOULD be computed using alpha=1/8 and beta=1/4 (as suggested in [JK88]).
            // After the computation, a host MUST update RTO <- SRTT + max (G, K*RTTVAR).
            const ALPHA: f64 = 1.0 / 8.0;
            const BETA: f64 = 1.0 / 4.0;

            comp.rttvar = (1.0 - BETA) * comp.rttvar + BETA * (comp.srtt - r).abs();
            comp.srtt = (1.0 - ALPHA) * comp.srtt + ALPHA * r;
            self.rto = comp.srtt + (4.0 * comp.rttvar).max(G);
        } else {
            // (2.2) When the first RTT measurement R is made, the host MUST set
            //      SRTT <- R
            //      RTTVAR <- R/2
            //      RTO <- SRTT + max (G, K*RTTVAR)
            //  where K = 4.
            self.running = Some(SmoothedRTT {
                srtt: r,
                rttvar: r / 2.0,
                nto: 0,
            });
            self.rto = r + (2.0 * r).max(G);
        }

        // (2.4)  Whenever RTO is computed, if it is less than 1 second, then the
        // RTO SHOULD be rounded up to 1 second.
        self.rto = self.rto.max(1.0);

        // (2.5) A maximum value MAY be placed on RTO provided it is at least 60 seconds.
        self.rto = self.rto.min(60.0);
    }

    pub fn should_retransmit(&mut self, una: u32, now: SimTime) -> bool {
        let waited_for = self.send_times.range(una..).next().map(|t| now - *t.1);

        tracing::trace!("{waited_for:?} {}", self.rto);

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for >= Duration::from_secs(1) && waited_for.as_secs_f64() >= 1.5 * self.rto
        } else {
            false
        };

        should_retransmit
    }

    pub fn on_timeout(&mut self, _is_ack_of_syn: bool) {
        // (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
        // maximum value discussed in (2.5) above may be used to provide
        // an upper bound to this doubling operation.
        self.rto = 2.0 * self.rto;
        self.rto = self.rto.min(60.0);

        // Note that a TCP implementation MAY clear SRTT and RTTVAR after
        // backing off the timer multiple times as it is likely that the current
        // SRTT and RTTVAR are bogus in this situation.  Once SRTT and RTTVAR
        // are cleared, they should be initialized with the next RTT sample
        // taken per (2.2) rather than using (2.3).
        if let Some(ref mut running) = self.running {
            running.nto += 1;

            if running.nto >= 3 {
                self.running = None;
            }
        }

        // TODO: on ACK of SYN, reset to 3s once established
    }
}

#[cfg(test)]
mod tests {
    use rand::random;
    use std::iter;

    use super::*;

    #[test]
    fn rto_computation_first_meassurement() {
        let mut timers = Timers::new(&Config::test_default());
        assert_eq!(timers.rto, 10.0); // initial_rto = 10s

        timers.on_meassurement(1.3);
        assert_eq!(timers.rto, 3.9000000000000004);

        assert_eq!(timers.running.as_ref().map(|v| v.srtt), Some(1.3));
        assert_eq!(timers.running.as_ref().map(|v| v.rttvar), Some(1.3 / 2.0));
    }

    #[test]
    fn rto_minimum_value() {
        let mut timers = Timers::new(&Config::test_default());
        for r in iter::repeat_with(|| random::<f64>()).take(1000) {
            timers.on_meassurement(r);
            assert!(timers.rto >= 1.0);
        }
    }

    #[test]
    fn rto_maximum_value() {
        let mut timers = Timers::new(&Config::test_default());
        for r in iter::repeat_with(|| random::<f64>()).take(1000) {
            timers.on_meassurement(60.0 + 10.0 * r);
            assert!(timers.rto <= 60.0);
        }
    }

    fn rto_default_setup() -> Timers {
        let mut timers = Timers::new(&Config::test_default());
        for r in [0.7, 0.78, 0.64, 0.63, 0.67, 0.6] {
            timers.on_meassurement(r);
        }
        timers
    }

    #[test]
    fn rto_doubles_at_timeout() {
        let mut timers = rto_default_setup();

        let prev_rto = timers.rto;
        timers.on_timeout(false);
        assert_eq!(timers.rto, prev_rto * 2.0);
    }

    #[test]
    fn srtt_reset_after_multiple_timeouts() {
        let mut timers = rto_default_setup();

        let prev_rto = timers.rto;
        assert!(timers.running.is_some());
        timers.on_timeout(false);
        assert!(timers.running.is_some());
        timers.on_timeout(false);
        assert!(timers.running.is_some());
        timers.on_timeout(false);

        assert_eq!(timers.rto, 8.0 * prev_rto);
        assert!(timers.running.is_none());
    }

    #[test]
    fn recv_emitts_one_sample() {
        let mut timers = Timers::new(&Config::test_default());

        timers.on_send(1, 1.0.into());
        timers.on_send(101, 1.2.into());

        timers.on_recv(1, 101, 2.0.into());
        assert_eq!(timers.running.as_ref().map(|v| v.srtt), Some(1.0));

        timers.on_recv(101, 201, 2.2.into());
        assert_eq!(timers.rto, 2.5)
    }

    #[test]
    fn recv_emitts_multiple_samples() {
        let mut timers = Timers::new(&Config::test_default());

        timers.on_send(1, 1.0.into());
        timers.on_send(101, 1.2.into());

        timers.on_recv(1, 201, 2.0.into());
        assert_ne!(timers.running.as_ref().map(|v| v.srtt), Some(1.0));
        assert_eq!(timers.rto, 2.675)
    }

    #[test]
    fn recv_drops_timers() {
        let mut timers = Timers::new(&Config::test_default());

        timers.on_send(1, 1.0.into());
        timers.on_send(101, 1.2.into());

        assert_eq!(timers.send_times.len(), 2);
        timers.on_recv(1, 101, 2.0.into());
        assert_eq!(timers.send_times.len(), 1);
    }
}

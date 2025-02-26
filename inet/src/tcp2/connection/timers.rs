use super::{is_between_wrapped, Config};
use des::time::SimTime;
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

//
// # Segment timers
//

/// RFC 6298 - Computing TCP's Retransmission Timer
///
/// To compute the current RTO, a TCP sender maintains two state
/// variables, SRTT (smoothed round-trip time) and RTTVAR (round-trip
/// time variation).  In addition, we assume a clock granularity of G
/// seconds.
#[derive(Debug, Clone)]
pub struct RetranssmissionTimers {
    /// (seg.seqn, (send-time, retransmission))
    pub segments: BTreeMap<u32, Entry>,

    pub rto: f64,
    pub running: Option<SmoothedRTT>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub sent: SimTime,
    pub timeout: SimTime,
    pub is_retransmission: bool,
}

#[derive(Debug, Clone)]
pub struct SmoothedRTT {
    pub srtt: f64,
    pub rttvar: f64,
    pub nto: usize,
}

impl RetranssmissionTimers {
    pub fn new(cfg: &Config) -> Self {
        // (2.1) Until a round-trip time (RTT) measurement has been made for a
        // segment sent between the sender and receiver, the sender SHOULD
        // set RTO <- 1 second.
        Self {
            segments: Default::default(),

            rto: cfg.initial_rto.as_secs_f64(),
            running: None,
        }
    }

    fn next_timeout(&self) -> Option<SimTime> {
        self.segments.values().map(|v| v.timeout).min()
    }

    pub fn register_segment(&mut self, seq: u32, is_retransmission: bool, now: SimTime) {
        self.segments.insert(
            seq,
            Entry {
                sent: now,
                timeout: now + self.rto,
                is_retransmission,
            },
        );
    }

    pub fn update_send_time(&mut self, seg: u32, now: SimTime) {
        if let Some(entry) = self.segments.get_mut(&seg) {
            let offset = now - entry.sent;
            entry.sent = now;
            entry.timeout += offset;
        }
    }

    pub fn on_recv(&mut self, una: u32, ackn: u32, now: SimTime) {
        let mut meassurements = Vec::new();

        self.segments.retain(|&seq, entry| {
            if is_between_wrapped(una, seq, ackn) {
                let elapsed = (now - entry.sent).as_secs_f64();
                if !entry.is_retransmission {
                    meassurements.push(elapsed);
                }
                false
            } else {
                true
            }
        });

        meassurements
            .into_iter()
            .for_each(|m| self.add_meassurement(m));
    }

    pub fn add_meassurement(&mut self, r: f64) {
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

    pub fn expired(&mut self, una: u32, now: SimTime) -> Vec<u32> {
        self.segments.retain(|v, _| *v >= una);
        self.segments
            .range(una..)
            .filter(|(_, e)| now >= e.timeout)
            .map(|v| *v.0)
            .collect()
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

//
// # Other timers
//

#[derive(Debug, Clone)]
pub struct Timers {
    rtt: RetranssmissionTimers,
    time_wait_to: Option<SimTime>,
}

impl Timers {
    pub fn new(cfg: &Config) -> Self {
        Self {
            rtt: RetranssmissionTimers::new(cfg),
            time_wait_to: None,
        }
    }

    pub fn set_timewait_to(&mut self, now: SimTime) {
        self.time_wait_to = Some(now + self.rtt.rto * 2.0);
    }

    pub fn timewait_to_expired(&self, now: SimTime) -> bool {
        self.time_wait_to.map_or(false, |to| now >= to)
    }

    pub fn next_timeout(&self) -> Option<SimTime> {
        self.rtt
            .next_timeout()
            .map(|a| self.time_wait_to.map_or(a, |b| a.min(b)))
    }
}

impl Deref for Timers {
    type Target = RetranssmissionTimers;
    fn deref(&self) -> &Self::Target {
        &self.rtt
    }
}

impl DerefMut for Timers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rtt
    }
}

#[cfg(test)]
mod tests {
    use rand::random;
    use std::iter;

    use super::*;

    #[test]
    fn rto_computation_first_meassurement() {
        let mut timers = RetranssmissionTimers::new(&Config::test_default());
        assert_eq!(timers.rto, 10.0); // initial_rto = 10s

        timers.add_meassurement(1.3);
        assert_eq!(timers.rto, 3.9000000000000004);

        assert_eq!(timers.running.as_ref().map(|v| v.srtt), Some(1.3));
        assert_eq!(timers.running.as_ref().map(|v| v.rttvar), Some(1.3 / 2.0));
    }

    #[test]
    fn rto_minimum_value() {
        let mut timers = RetranssmissionTimers::new(&Config::test_default());
        for r in iter::repeat_with(|| random::<f64>()).take(1000) {
            timers.add_meassurement(r);
            assert!(timers.rto >= 1.0);
        }
    }

    #[test]
    fn rto_maximum_value() {
        let mut timers = RetranssmissionTimers::new(&Config::test_default());
        for r in iter::repeat_with(|| random::<f64>()).take(1000) {
            timers.add_meassurement(60.0 + 10.0 * r);
            assert!(timers.rto <= 60.0);
        }
    }

    fn rto_default_setup() -> RetranssmissionTimers {
        let mut timers = RetranssmissionTimers::new(&Config::test_default());
        for r in [0.7, 0.78, 0.64, 0.63, 0.67, 0.6] {
            timers.add_meassurement(r);
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
        let mut timers = RetranssmissionTimers::new(&Config::test_default());

        timers.register_segment(1, false, 1.0.into());
        timers.register_segment(101, false, 1.2.into());

        timers.on_recv(1, 101, 2.0.into());
        assert_eq!(timers.running.as_ref().map(|v| v.srtt), Some(1.0));

        timers.on_recv(101, 201, 2.2.into());
        assert_eq!(timers.rto, 2.5)
    }

    #[test]
    fn recv_emitts_multiple_samples() {
        let mut timers = RetranssmissionTimers::new(&Config::test_default());

        timers.register_segment(1, false, 1.0.into());
        timers.register_segment(101, false, 1.2.into());

        timers.on_recv(1, 201, 2.0.into());
        assert_ne!(timers.running.as_ref().map(|v| v.srtt), Some(1.0));
        assert_eq!(timers.rto, 2.675)
    }

    #[test]
    fn recv_drops_timers() {
        let mut timers = RetranssmissionTimers::new(&Config::test_default());

        timers.register_segment(1, false, 1.0.into());
        timers.register_segment(101, false, 1.2.into());

        assert_eq!(timers.segments.len(), 2);
        timers.on_recv(1, 101, 2.0.into());
        assert_eq!(timers.segments.len(), 1);
    }

    #[test]
    fn recv_retransmit_is_no_meassurement() {
        let mut timers = rto_default_setup();

        timers.register_segment(1, false, 1.0.into());
        timers.register_segment(1, true, 2.0.into());

        let rto = timers.rto;
        timers.on_recv(1, 101, 2.2.into());
        assert_eq!(timers.rto, rto);
    }
}

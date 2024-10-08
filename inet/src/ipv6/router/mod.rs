use des::time::SimTime;
use types::{
    icmpv6::{NDP_MAX_DELAY_BETWEEN_RAS, NDP_MIN_DELAY_BETWEEN_RAS},
    ip::{Ipv6LongestPrefixTable, Ipv6Prefix},
};
use rand::distributions::Uniform;
use std::{io, net::Ipv6Addr, time::Duration};

use crate::{ctx::IOContext, interface::IfId};

mod api;
pub use api::*;

use super::timer::TimerToken;

pub struct RouterState {
    pub last_adv_sent: SimTime,
}

impl RouterState {
    pub fn new() -> Self {
        Self {
            last_adv_sent: SimTime::MAX,
        }
    }
}

/// A prefix matching routing table
#[derive(Debug)]
pub struct Router {
    pub entries: Ipv6LongestPrefixTable<Entry>,
}

#[derive(Debug)]
pub struct Entry {
    pub prefix: Ipv6Prefix,
    pub next_hop: Ipv6Addr,
    pub ifid: IfId,
    pub expires: SimTime,
}

impl Router {
    pub fn new() -> Self {
        Router {
            entries: Ipv6LongestPrefixTable::new(),
        }
    }

    pub fn lookup(&self, dst: Ipv6Addr) -> Option<(Ipv6Addr, IfId)> {
        if dst.is_multicast() {
            return Some((dst, IfId::NULL));
        }
        self.entries
            .iter()
            .find(|e| e.prefix.contains(dst))
            .map(|e| (e.next_hop, e.ifid))
            .map(|e| {
                tracing::trace!("choose route towards {dst} -> {} over {}", e.0, e.1);
                e
            })
    }

    pub fn add(&mut self, prefix: Ipv6Prefix, next_hop: Ipv6Addr, ifid: IfId, expires: SimTime) {
        let entry = Entry {
            prefix,
            next_hop,
            ifid,
            expires,
        };
        self.entries.insert(prefix, entry);
    }

    pub fn time_out_entries(&mut self, until: SimTime) {
        self.entries.retain(|_, entry| entry.expires > until);
    }
}

impl IOContext {
    pub fn ipv6_schedule_unsolicited_router_adv(&mut self, ifid: IfId) -> io::Result<()> {
        let token = TimerToken::RouterAdvertismentUnsolicited { ifid };
        if self.ipv6.timer.active(&token).is_none() {
            let timeout = SimTime::now()
                + Duration::from_secs_f64(des::runtime::sample(Uniform::new(
                    NDP_MIN_DELAY_BETWEEN_RAS.as_secs_f64(),
                    NDP_MAX_DELAY_BETWEEN_RAS.as_secs_f64(),
                )));
            self.ipv6.timer.schedule(token, timeout);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn router_times_out_entries() -> Result<(), Box<dyn Error>> {
        let en0 = IfId::new("en0");
        let en1 = IfId::new("en1");

        let mut router = Router::new();
        router.add(
            "2003:1234::/64".parse()?,
            "2003:1234::cbab:1234".parse()?,
            en0,
            100.0.into(),
        );
        router.add(
            "2004:1234::/64".parse()?,
            "2004:1234::cbab:1234".parse()?,
            en1,
            200.0.into(),
        );
        router.add(
            "2005:1234::/64".parse()?,
            "2005:1234::cbab:1234".parse()?,
            en0,
            SimTime::MAX,
        );

        router.time_out_entries(50.0.into());
        assert_eq!(router.entries.len(), 3);
        assert_eq!(
            router.lookup("2003:1234::1234".parse()?),
            Some(("2003:1234::cbab:1234".parse()?, en0))
        );

        router.time_out_entries(100.0.into());
        assert_eq!(router.entries.len(), 2);
        assert_eq!(router.lookup("2003:1234::1234".parse()?), None);

        router.time_out_entries(1000.0.into());
        assert_eq!(router.entries.len(), 1);

        Ok(())
    }
}

use std::{collections::VecDeque, time::Duration};

use des::time::SimTime;
use types::tcp::TcpPacket;

use super::wrapping_lt;

#[derive(Debug, Default)]
pub struct ReorderBuffer {
    pub pkts: VecDeque<(SimTime, TcpPacket)>,
}

impl ReorderBuffer {
    pub fn enqueue(&mut self, pkt: TcpPacket, t: SimTime) {
        tracing::trace!(?pkt.flags, ?pkt.seq_no, ?pkt.ack_no, ?pkt.window, pkt.content=pkt.content.len(), "enqueing out-of-order packet");
        match self
            .pkts
            .binary_search_by_key(&pkt.seq_no, |(_, pkt)| pkt.seq_no)
        {
            Ok(i) | Err(i) => self.pkts.insert(i, (t, pkt)),
        }
    }

    pub fn update(&mut self, t: SimTime, max_store_time: Duration) {
        self.pkts
            .retain(|(event_t, _)| (dbg!(t) - dbg!(*event_t)) <= dbg!(max_store_time));
    }

    /// `expected = RCV.NXT`
    pub fn next(&mut self, expected: u32) -> Option<TcpPacket> {
        let (_, canidate) = self.pkts.front()?;
        // <= LTE
        if wrapping_lt(canidate.seq_no, expected.wrapping_add(1)) {
            let (_, mut seg) = self.pkts.pop_front()?;
            let trunc_len = expected.wrapping_sub(seg.seq_no) as usize;
            dbg!(trunc_len, seg.content.len());
            if trunc_len >= seg.content.len() {
                // skip this packet
                return self.next(expected);
            }

            drop(seg.content.drain(..trunc_len));
            seg.seq_no = seg.seq_no.wrapping_add(trunc_len as u32);
            Some(seg)
        } else {
            None
        }
    }
}

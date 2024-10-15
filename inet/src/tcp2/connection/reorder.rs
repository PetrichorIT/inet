use std::collections::VecDeque;

use types::tcp::TcpPacket;

use super::wrapping_lt;

#[derive(Debug, Default)]
pub(crate) struct ReorderBuffer {
    pub pkts: VecDeque<TcpPacket>,
}

impl ReorderBuffer {
    pub fn enqueue(&mut self, pkt: TcpPacket) {
        tracing::trace!(?pkt, "enqueing out-of-order packet");
        match self
            .pkts
            .binary_search_by_key(&pkt.seq_no, |pkt| pkt.seq_no)
        {
            Ok(i) | Err(i) => self.pkts.insert(i, pkt),
        }
    }

    /// `expected = RCV.NXT`
    pub fn next(&mut self, expected: u32) -> Option<TcpPacket> {
        let canidate = self.pkts.front()?;
        // <= LTE
        if wrapping_lt(canidate.seq_no, expected.wrapping_add(1)) {
            let mut seg = self.pkts.pop_front()?;
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

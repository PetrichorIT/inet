use std::{collections::VecDeque, time::Duration};

use bytes_io::Buf;
use des::time::SimTime;
use types::tcp::{TcpOption, TcpPacket};

use super::{Config, wrapping_lt};

#[derive(Debug, Default)]
pub struct ReorderBuffer {
    pub sack: bool,
    pub pkts: VecDeque<(SimTime, TcpPacket)>,
}

impl ReorderBuffer {
    pub fn from_syn(syn: &TcpPacket, cfg: &Config) -> Self {
        Self {
            sack: syn
                .options
                .contains(&TcpOption::SelectiveAcknowledgementPermitted)
                && cfg.enable_sack,
            pkts: VecDeque::new(),
        }
    }

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
            .retain(|(event_t, _)| (t - *event_t) <= max_store_time);
    }

    /// `expected = RCV.NXT`
    pub fn next(&mut self, expected: u32) -> Option<TcpPacket> {
        let (_, canidate) = self.pkts.front()?;
        // <= LTE
        if wrapping_lt(canidate.seq_no, expected.wrapping_add(1)) {
            let (_, mut seg) = self.pkts.pop_front()?;
            let trunc_len = expected.wrapping_sub(seg.seq_no) as usize;
            if trunc_len >= seg.content.len() {
                // skip this packet
                return self.next(expected);
            }

            seg.content.advance(trunc_len);
            seg.seq_no = seg.seq_no.wrapping_add(trunc_len as u32);
            Some(seg)
        } else {
            None
        }
    }

    /// Generates a sequence of "regions" in the current sequence space that
    /// are already in the sequence space. Combines multiple packets into a single region.
    pub fn sacks(&self) -> Vec<(u32, u32)> {
        let mut sacks = Vec::new();
        let mut current = None;

        for (_, pkt) in &self.pkts {
            if let Some((from, to)) = &mut current {
                if *to == pkt.seq_no {
                    // extend
                    *to += pkt.content.len() as u32;
                } else {
                    sacks.push((*from, *to));
                    current = Some((pkt.seq_no, pkt.seq_no + pkt.content.len() as u32));
                }
            } else {
                current = Some((pkt.seq_no, pkt.seq_no + pkt.content.len() as u32))
            }
        }

        sacks.extend(current);

        sacks.truncate(4);
        sacks
    }
}

#[cfg(test)]
mod tests {
    use rand::{rng, seq::SliceRandom};

    use super::*;

    const WIN_4KB: u16 = 4096;

    #[test]
    fn sacks_generated() {
        let mut buf = ReorderBuffer::default();
        buf.enqueue(
            TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50]),
            0.0.into(),
        );
        buf.enqueue(
            TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50]),
            0.0.into(),
        );
        buf.enqueue(
            TcpPacket::new(80, 1808, 4200, 1, WIN_4KB, vec![6; 50]),
            0.0.into(),
        );

        assert_eq!(buf.sacks(), [(4050, 4150), (4200, 4250)])
    }

    #[test]
    fn sorted_in_order_input() {
        let mut buf = ReorderBuffer::default();
        buf.enqueue(
            TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![1; 50]),
            0.0.into(),
        );
        buf.enqueue(
            TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50]),
            0.0.into(),
        );
        buf.enqueue(
            TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50]),
            0.0.into(),
        );

        assert_eq!(
            buf.pkts,
            [
                (
                    0.0.into(),
                    TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![1; 50])
                ),
                (
                    0.0.into(),
                    TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50])
                ),
                (
                    0.0.into(),
                    TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50])
                )
            ]
        )
    }

    #[test]
    fn sorted_fuzz_input() {
        for _ in 0..8 {
            let mut buf = ReorderBuffer::default();

            let mut pkts = vec![
                TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![1; 50]),
                TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50]),
                TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50]),
            ];
            pkts.shuffle(&mut rng());
            for pkt in pkts {
                buf.enqueue(pkt, 0.0.into());
            }

            assert_eq!(
                buf.pkts,
                [
                    (
                        0.0.into(),
                        TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![1; 50])
                    ),
                    (
                        0.0.into(),
                        TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50])
                    ),
                    (
                        0.0.into(),
                        TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50])
                    )
                ]
            )
        }
    }

    #[test]
    fn no_next_if_expected_not_reached() {
        let mut buf = ReorderBuffer::default();
        buf.enqueue(
            TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]),
            0.0.into(),
        );

        assert_eq!(buf.next(3500), None);
        assert_eq!(buf.next(3999), None);
    }

    #[test]
    fn next_at_exact_match() {
        let mut buf = ReorderBuffer::default();
        buf.enqueue(
            TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]),
            0.0.into(),
        );

        assert_eq!(
            buf.next(4000),
            Some(TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]))
        );
        assert_eq!(buf.pkts, []);
    }

    #[test]
    fn next_at_overreaching_match_trunc() {
        let mut buf = ReorderBuffer::default();
        buf.enqueue(
            TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]),
            0.0.into(),
        );

        assert_eq!(
            buf.next(4200),
            Some(TcpPacket::new(80, 1808, 4200, 1, WIN_4KB, vec![5; 300]))
        );
    }

    #[test]
    fn next_at_overreaching_match_skip_packets() {
        let mut buf = ReorderBuffer::default();
        buf.enqueue(
            TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]),
            0.0.into(),
        );
        buf.enqueue(
            TcpPacket::new(80, 1808, 4500, 1, WIN_4KB, vec![6; 500]),
            0.0.into(),
        );

        assert_eq!(
            buf.next(4500),
            Some(TcpPacket::new(80, 1808, 4500, 1, WIN_4KB, vec![6; 500]))
        );
    }

    #[test]
    fn discards_old_packets() {
        let mut buf = ReorderBuffer::default();
        buf.enqueue(
            TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]),
            0.0.into(),
        );
        buf.enqueue(
            TcpPacket::new(80, 1808, 4500, 1, WIN_4KB, vec![6; 500]),
            1.0.into(),
        );

        buf.update(1.2.into(), Duration::from_secs_f64(0.5));
        assert_eq!(
            buf.pkts,
            [(
                1.0.into(),
                TcpPacket::new(80, 1808, 4500, 1, WIN_4KB, vec![6; 500]),
            )]
        );
    }
}

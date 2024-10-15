use rand::{seq::SliceRandom, thread_rng};
use types::tcp::TcpPacket;

use crate::tcp2::connection::ReorderBuffer;

use super::WIN_4KB;

#[test]
fn buffer_sorted_in_order_input() {
    let mut buf = ReorderBuffer::default();
    buf.enqueue(TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![1; 50]));
    buf.enqueue(TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50]));
    buf.enqueue(TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50]));

    assert_eq!(
        buf.pkts,
        [
            TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![1; 50]),
            TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50]),
            TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50])
        ]
    )
}

#[test]
fn buffer_sorted_fuzz_input() {
    for _ in 0..8 {
        let mut buf = ReorderBuffer::default();

        let mut pkts = vec![
            TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![1; 50]),
            TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50]),
            TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50]),
        ];
        pkts.shuffle(&mut thread_rng());
        for pkt in pkts {
            buf.enqueue(pkt);
        }

        assert_eq!(
            buf.pkts,
            [
                TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![1; 50]),
                TcpPacket::new(80, 1808, 4050, 1, WIN_4KB, vec![2; 50]),
                TcpPacket::new(80, 1808, 4100, 1, WIN_4KB, vec![3; 50])
            ]
        )
    }
}

#[test]
fn buffer_no_next_if_expected_not_reached() {
    let mut buf = ReorderBuffer::default();
    buf.enqueue(TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]));

    assert_eq!(buf.next(3500), None);
    assert_eq!(buf.next(3999), None);
}

#[test]
fn buffer_next_at_exact_match() {
    let mut buf = ReorderBuffer::default();
    buf.enqueue(TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]));

    assert_eq!(
        buf.next(4000),
        Some(TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]))
    );
    assert_eq!(buf.pkts, []);
}

#[test]
fn buffer_next_at_overreaching_match_trunc() {
    let mut buf = ReorderBuffer::default();
    buf.enqueue(TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]));

    assert_eq!(
        buf.next(4200),
        Some(TcpPacket::new(80, 1808, 4200, 1, WIN_4KB, vec![5; 300]))
    );
}

#[test]
fn buffer_next_at_overreaching_match_skip_packets() {
    let mut buf = ReorderBuffer::default();
    buf.enqueue(TcpPacket::new(80, 1808, 4000, 1, WIN_4KB, vec![5; 500]));
    buf.enqueue(TcpPacket::new(80, 1808, 4500, 1, WIN_4KB, vec![6; 500]));

    assert_eq!(
        buf.next(4500),
        Some(TcpPacket::new(80, 1808, 4500, 1, WIN_4KB, vec![6; 500]))
    );
}

use std::{io::ErrorKind, time::Duration};

use des::time::SimTime;
use fxhash::FxHashMap;
use types::{
    icmpv6::IcmpV6TimeExceededCode,
    ip::{Ipv6ExtensionHeader, Ipv6Packet},
};

use crate::{
    ctx::IOContext,
    interface::IfId,
    io,
    ipv6::timer::{TimerCtrl, TimerToken},
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FragmentStore {
    mapping: FxHashMap<u32, Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    packets: Vec<Ipv6Packet>,
    deadline: SimTime,
}

impl FragmentStore {
    pub fn on_packet(
        &mut self,
        pkt: Ipv6Packet,
        ifid: IfId,
        timer: &mut TimerCtrl,
    ) -> Option<Ipv6Packet> {
        let Some(header) = pkt.extension_headers.iter().find_map(|h| match h {
            Ipv6ExtensionHeader::Fragment(frag) => Some(frag),
            _ => None,
        }) else {
            return Some(pkt);
        };

        let identification = header.identification;
        tracing::trace!("fragment for {identification} received on <{ifid}>");

        let entry = self.mapping.entry(identification).or_insert_with(|| Entry {
            packets: Vec::new(),
            deadline: SimTime::now() + Duration::from_secs(60),
        });

        entry.packets.push(pkt);
        timer.reschedule(
            &TimerToken::FragmentReassembly {
                identification,
                ifid,
            },
            entry.deadline,
        );

        self.yield_value(identification)
    }

    fn yield_value(&mut self, identification: u32) -> Option<Ipv6Packet> {
        let entry = self.mapping.get_mut(&identification)?;
        match Ipv6Packet::from_fragments(&mut entry.packets) {
            Ok(pkt) => {
                self.mapping.remove(&identification);
                Some(pkt)
            }
            Err(e) => {
                if e.kind() != ErrorKind::InvalidData {
                    self.mapping.remove(&identification);
                    tracing::error!("reassembly error: {e}");
                    // real error
                }
                None
            }
        }
    }

    // Times out a reassembly and returns the first packet if exists
    // -> to send ICMP
    // -> if not present, no ICMP
    pub fn timeout(&mut self, identification: u32) -> Option<Ipv6Packet> {
        let entry = self.mapping.remove(&identification)?;
        for pkt in entry.packets {
            if pkt.extension_headers.iter().any(|h| match h {
                Ipv6ExtensionHeader::Fragment(frag) => frag.fragment_offset == 0,
                _ => false,
            }) {
                return Some(pkt);
            }
        }
        None
    }
}

impl IOContext {
    pub(super) fn ipv6_fragment_reassembly_timeout(
        &mut self,
        ifid: IfId,
        identification: u32,
    ) -> io::Result<()> {
        let Some(start_packet) = self.ipv6.fragments.timeout(identification) else {
            return Ok(());
        };

        self.ipv6_icmp_send_time_exceeded(
            &start_packet,
            ifid,
            IcmpV6TimeExceededCode::FragmentReassemblyTimeExceeded,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv6Addr, time::Duration};

    use bytes_io::{Bytes, FromBytes};
    use des::{
        globals,
        prelude::{Message, current, send},
        time::sleep,
    };
    use rand::{Rng, rng};
    use serial_test::serial;
    use types::{
        icmpv6::{IcmpV6Packet, IcmpV6TimeExceeded, IcmpV6TimeExceededCode, PROTO_ICMPV6},
        iface::MacAddress,
        ip::{Ipv6Packet, KIND_IPV6},
        udp::PROTO_UDP,
    };

    use crate::{
        UdpSocket,
        ipv6::socket::RawV6Socket,
        utils::{SimpleSim, get_mac_address},
    };

    #[test]
    #[serial]
    fn recv_very_large_fragment() -> Result<(), des::Failure> {
        // des::tracing::init();

        let mut sim = SimpleSim::default();
        sim.v6 = true;
        let large_bytes = rng().random::<[u8; 10_000]>();
        let large_bytes_2 = large_bytes.clone();

        sim.node_require_join("alice", move || async move {
            let sock = UdpSocket::bind("[::]:0").await?;
            let n = sock.send_to(&large_bytes, ("bob", 100)).await?;
            assert_eq!(n, 10_000);
            Ok(())
        });

        sim.node_require_join("bob", move || async move {
            let sock = UdpSocket::bind("[::]:100").await?;
            let mut buf = [0; 12_000];
            let (n, _) = sock.recv_from(&mut buf).await?;
            assert_eq!(&buf[..n], large_bytes_2);

            Ok(())
        });

        sim.run()
    }

    #[test]
    #[serial]
    fn fragmentation_timeout_after_60s() -> Result<(), des::Failure> {
        // des::tracing::init();

        let mut sim = SimpleSim::default();
        sim.v6 = true;
        let large_bytes = rng().random::<[u8; 10_000]>();

        sim.node_require_join("fe80::1234", move || async move {
            sleep(Duration::from_secs(1)).await;

            let mac: MacAddress = globals()
                .get(&"fe80::abcd")
                .unwrap()
                .prop("mac")
                .unwrap()
                .get()
                .unwrap();

            let pkt = Ipv6Packet {
                flow_label: 0,
                traffic_class: 0,
                proto: PROTO_UDP,
                hop_limit: 64,
                extension_headers: Vec::new(),
                src: "fe80::1234".parse().unwrap(),
                dst: "fe80::abcd".parse().unwrap(),
                content: Bytes::copy_from_slice(&large_bytes),
            };
            let mut fragments = pkt.fragment_to_mtu(1280, 555);
            fragments.remove(2);
            for frag in &fragments {
                let _ = send(
                    Message::default()
                        .with_kind(KIND_IPV6)
                        .with_dst(mac.into())
                        .with_content(frag.clone()),
                    "port",
                );
            }

            let mut sock = RawV6Socket::new(PROTO_ICMPV6)?;
            sock.bind(Ipv6Addr::UNSPECIFIED)?;

            loop {
                let pkt = sock.recv().await?;
                let icmp = IcmpV6Packet::peek_from(pkt.content)?;

                if matches!(
                    icmp,
                    IcmpV6Packet::NeighborSolicitation(_) | IcmpV6Packet::NeighborAdvertisment(_)
                ) {
                    continue;
                }

                if matches!(
                    icmp,
                    IcmpV6Packet::TimeExceeded(IcmpV6TimeExceeded {
                        code: IcmpV6TimeExceededCode::FragmentReassemblyTimeExceeded,
                        ..
                    })
                ) {
                    break;
                }
            }

            Ok(())
        });

        sim.node_require_join("fe80::abcd", move || async move {
            current()
                .prop("mac")
                .unwrap()
                .set(get_mac_address()?.unwrap());

            Ok(())
        });

        sim.run()
    }
}

use std::{io, net::Ipv6Addr};

use des::time::SimTime;
use fxhash::FxHashMap;
use types::{
    icmpv6::IcmpV6PacketToBig,
    ip::{IPV6_MINIMUM_MTU, Ipv6Packet},
    tcp::PROTO_TCP,
};

use crate::{ctx::IOContext, socket::SocketType};

#[derive(Debug, Default)]
pub struct PathMtuStore {
    mapping: FxHashMap<Ipv6Addr, Entry>,
}

#[derive(Debug)]
struct Entry {
    mtu: usize,
    _at: SimTime,
}

impl PathMtuStore {
    pub fn lookup(&self, dst: Ipv6Addr) -> Option<usize> {
        self.mapping.get(&dst).map(|v| v.mtu)
    }

    /// returns changed
    pub fn update(&mut self, dst: Ipv6Addr, mtu: usize) -> bool {
        if let Some(existing) = self.mapping.get_mut(&dst) {
            let is_different = existing.mtu != mtu;
            existing.mtu = mtu.min(existing.mtu);
            is_different
        } else {
            self.mapping.insert(
                dst,
                Entry {
                    mtu,
                    _at: SimTime::now(),
                },
            );
            true
        }
    }
}

impl IOContext {
    pub fn ipv6_get_path_mtu(&self, src: Ipv6Addr, dst: Ipv6Addr) -> usize {
        self.ipv6
            .path_mtu
            .lookup(dst)
            .unwrap_or_else(|| self.ipv6_get_local_mtu(src, dst))
    }

    pub fn ipv6_get_local_mtu(&self, mut src: Ipv6Addr, dst: Ipv6Addr) -> usize {
        const DEFAULT_UNKNOWN_MTU: usize = IPV6_MINIMUM_MTU - Ipv6Packet::MIN_HEADER_SIZE;

        if dst.is_unspecified() {
            return DEFAULT_UNKNOWN_MTU;
        }

        if src.is_unspecified() {
            // (0) Check link local
            let canidates = self.ipv6_src_addr_canidate_set(dst, None);
            if let Some(csrc) = canidates.select(&self.ipv6.policies) {
                src = csrc.addr;
            } else {
                return DEFAULT_UNKNOWN_MTU;
            }
        }

        let ifid = self.ipv6_ifid_for_src_addr(src);
        self.ifaces.get(&ifid).map_or(DEFAULT_UNKNOWN_MTU, |iface| {
            iface.device.mtu() - Ipv6Packet::MIN_HEADER_SIZE
        })
    }

    #[allow(clippy::single_match)]
    pub(super) fn ipv6_icmp_recv_packet_to_big(
        &mut self,
        ip: &Ipv6Packet,
        icmp: IcmpV6PacketToBig,
        original_trunc: &Ipv6Packet,
    ) -> Result<bool, io::Error> {
        tracing::warn!(
            cause = ?ip.src,
            original = ?(original_trunc.src, original_trunc.dst),
            "received ICMPV6 PacketTooBig allowed={}",
            icmp.mtu
        );

        // (1) record MTU for further use
        let changed = self
            .ipv6
            .path_mtu
            .update(original_trunc.dst, icmp.mtu as usize);

        if !changed {
            return Ok(true);
        }

        // (2) find affected sockets
        let affected = self
            .sockets
            .iter()
            .filter(|s| s.1.peer.ip() == original_trunc.dst)
            .map(|v| (*v.0, v.1.typ))
            .collect::<Vec<_>>();

        // (3) notify affected sockets
        use SocketType::*;
        for (fd, sock_typ) in affected {
            match (sock_typ, original_trunc.proto) {
                (SOCK_STREAM, PROTO_TCP) => self.tcp_on_mtu_change(fd, icmp.mtu as usize),
                _ => (),
            }
        }

        Ok(true)
    }
}

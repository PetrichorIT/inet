//! Multicast listener discovery

use std::{io, net::Ipv6Addr, time::Duration};

use bytepack::ToBytestream;
use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use inet_types::{
    icmpv6::{IcmpV6MulticastListenerMessage, IcmpV6Packet, PROTO_ICMPV6},
    ip::{Ipv6AddrExt, Ipv6AddrScope, Ipv6Packet},
};
use tracing::Level;

use crate::{ctx::IOContext, interface::IfId};

use super::{timer::TimerToken, Ipv6SendFlags};

const DEFAULT_UNSOLICITD_MAX_RESPONSE_DELAY: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Querier,
    NonQuerier,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    #[default]
    NonListener,
    IdleListener(bool),
    DelayedListener(bool, SimTime),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    StartListening,
    StopListening,
    QueryReceived(IcmpV6MulticastListenerMessage),
    ReportReceived(IcmpV6MulticastListenerMessage),
    TimerExpired(TimerToken),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    SendReport,
    SendDone,
    StartTimer(SimTime),
    ResetTimer(SimTime),
    StopTimer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastListenerDiscoveryCtrl {
    pub role: Role,
    pub query_response_interval: Duration,
    pub states: FxHashMap<Ipv6Addr, NodeState>,
}

impl Default for MulticastListenerDiscoveryCtrl {
    fn default() -> Self {
        Self {
            role: Role::NonQuerier,
            query_response_interval: Duration::from_secs(1),
            states: FxHashMap::with_hasher(FxBuildHasher::default()),
        }
    }
}

impl NodeState {
    fn on(
        self,
        event: Event,
        mut f: impl FnMut(Action) -> io::Result<()>,
    ) -> io::Result<NodeState> {
        match self {
            NodeState::NonListener => match event {
                Event::StartListening => {
                    f(Action::SendReport)?;
                    let deadline = SimTime::now()
                        + Duration::from_secs_f64(
                            DEFAULT_UNSOLICITD_MAX_RESPONSE_DELAY.as_secs_f64()
                                + des::runtime::random::<f64>(),
                        );
                    f(Action::StartTimer(deadline))?;
                    Ok(NodeState::DelayedListener(true, deadline))
                }
                _ => Ok(self),
            },
            NodeState::DelayedListener(flag, timer_state) => match event {
                Event::StopListening => {
                    f(Action::StopTimer)?;
                    if flag {
                        f(Action::SendDone)?;
                    }
                    Ok(NodeState::NonListener)
                }
                Event::QueryReceived(query) => {
                    // If max response delay < shrink timer
                    if SimTime::now() + query.maximum_response_delay < timer_state {
                        let new_deadline = SimTime::now()
                            + Duration::from_secs_f64(
                                query.maximum_response_delay.as_secs_f64()
                                    * des::runtime::random::<f64>(),
                            );
                        f(Action::ResetTimer(new_deadline))?;
                    }
                    Ok(self)
                }
                Event::TimerExpired(_token) => {
                    f(Action::SendReport)?;
                    Ok(NodeState::IdleListener(true))
                }
                Event::ReportReceived(_report) => {
                    f(Action::StopTimer)?;
                    Ok(NodeState::IdleListener(false))
                }
                _ => Ok(self),
            },
            NodeState::IdleListener(flag) => match event {
                Event::QueryReceived(query) => {
                    let deadline = SimTime::now()
                        + Duration::from_secs_f64(
                            query.maximum_response_delay.as_secs_f64()
                                + des::runtime::random::<f64>(),
                        );
                    f(Action::StartTimer(deadline))?;
                    Ok(NodeState::DelayedListener(flag, deadline))
                }
                Event::StopListening => {
                    if flag {
                        f(Action::SendDone)?;
                    }
                    Ok(NodeState::NonListener)
                }
                _ => Ok(self),
            },
        }
    }
}

impl IOContext {
    pub fn mld_on_event(
        &mut self,
        ifid: IfId,
        event: Event,
        multicast_addr: Ipv6Addr,
    ) -> io::Result<()> {
        let ctrl = self.ipv6.mld.entry(ifid).or_default();
        let state = *ctrl
            .states
            .get(&multicast_addr)
            .unwrap_or(&NodeState::default());

        let new_state = state.on(event, |action| match action {
            Action::SendReport => self.ipv6_icmp_send_mld_report(ifid, multicast_addr),
            Action::SendDone => self.ipv6_icmp_send_mld_done(ifid, multicast_addr),
            Action::StartTimer(deadline) => {
                let token = TimerToken::MulticastListenerDiscoverySendReport {
                    ifid,
                    multicast_addr,
                };
                self.ipv6.timer.schedule(token, deadline);
                Ok(())
            }
            Action::ResetTimer(new_deadline) => {
                let token = TimerToken::MulticastListenerDiscoverySendReport {
                    ifid,
                    multicast_addr,
                };
                self.ipv6.timer.reschedule(&token, new_deadline);
                Ok(())
            }
            Action::StopTimer => {
                let token = TimerToken::MulticastListenerDiscoverySendReport {
                    ifid,
                    multicast_addr,
                };
                self.ipv6.timer.cancel(&token);
                Ok(())
            }
        })?;

        let ctrl = self.ipv6.mld.entry(ifid).or_default();
        ctrl.states.insert(multicast_addr, new_state);

        Ok(())
    }

    pub fn ipv6_icmp_recv_multicast_listener_query(
        &mut self,
        _pkt: &Ipv6Packet,
        ifid: IfId,
        query: IcmpV6MulticastListenerMessage,
    ) -> io::Result<bool> {
        // let ctrl = self
        //     .ipv6
        //     .mld
        //     .entry(ifid)
        //     .or_insert(MulticastListenerDiscoveryCtrl::default());

        let general_query = query.multicast_addr == Ipv6Addr::UNSPECIFIED;
        if general_query {
            // Schedule a report for all assigned multicast querys
            let addrs = self
                .ifaces
                .get(&ifid)
                .expect("unknow interface")
                .addrs
                .multicast_scopes()
                .into_iter()
                .filter(|(addr, _)| addr.scope() > Ipv6AddrScope::InterfaceLocal) // only with great scopes
                .filter(|(addr, _)| *addr != Ipv6Addr::MULTICAST_ALL_NODES)
                .copied()
                .collect::<Vec<_>>();

            for (addr, _) in addrs {
                self.mld_on_event(ifid, Event::QueryReceived(query.clone()), addr)?;
            }
        } else {
            assert!(query.multicast_addr.is_multicast());
            let addr = query.multicast_addr;
            self.mld_on_event(ifid, Event::QueryReceived(query), addr)?;
        }

        Ok(true)
    }

    fn ipv6_icmp_send_mld_report(&mut self, ifid: IfId, multicast: Ipv6Addr) -> io::Result<()> {
        let _guard = tracing::span!(Level::INFO, "iface", id=%ifid).entered();

        let iface = self.ifaces.get(&ifid).unwrap();
        if iface.flags.loopback {
            return Ok(());
        }

        let msg = IcmpV6Packet::MulticastListenerReport(IcmpV6MulticastListenerMessage {
            maximum_response_delay: Duration::ZERO,
            multicast_addr: multicast,
        });
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 1,
            src: Ipv6Addr::UNSPECIFIED,
            dst: multicast,
            content: msg.to_vec()?,
        };

        // TODO: this should ?? always use fe80 addrs, but what to do when no such addr is availabel ??
        self.ipv6_send_with_flags(pkt, ifid, Ipv6SendFlags::ALLOW_SRC_UNSPECIFIED)?;

        Ok(())
    }

    fn ipv6_icmp_send_mld_done(&mut self, ifid: IfId, multicast_addr: Ipv6Addr) -> io::Result<()> {
        let iface = self.ifaces.get(&ifid).unwrap();
        if iface.flags.loopback {
            return Ok(());
        }

        let msg = IcmpV6Packet::MulticastListenerDone(IcmpV6MulticastListenerMessage {
            maximum_response_delay: Duration::ZERO,
            multicast_addr,
        });
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 1,
            src: Ipv6Addr::UNSPECIFIED,
            dst: multicast_addr,
            content: msg.to_vec()?,
        };

        // TODO: this should ?? always use fe80 addrs, but what to do when no such addr is availabel ??
        self.ipv6_send_with_flags(pkt, ifid, Ipv6SendFlags::ALLOW_SRC_UNSPECIFIED)
    }

    pub fn ipv6_icmp_recv_multicast_listener_discovery_report(
        &mut self,
        _ip: &Ipv6Packet,
        ifid: IfId,
        report: IcmpV6MulticastListenerMessage,
    ) -> io::Result<bool> {
        let ctrl = self.ipv6.mld.entry(ifid).or_default();
        match ctrl.role {
            Role::Querier => {}
            Role::NonQuerier => {
                // If self is also scheduling a report for this MC address, cancel the report
                let token = TimerToken::MulticastListenerDiscoverySendReport {
                    ifid,
                    multicast_addr: report.multicast_addr,
                };
                self.ipv6.timer.cancel(&token);
            }
        }

        Ok(true)
    }
}

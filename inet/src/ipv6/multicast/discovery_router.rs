use bytes_io::ToBytes;
use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap};
use std::{io, net::Ipv6Addr, time::Duration};
use tracing::Level;
use types::{
    icmpv6::{IcmpV6MulticastListenerMessage, IcmpV6Packet, PROTO_ICMPV6},
    ip::{Ipv6AddrExt, Ipv6AddrScope, Ipv6Packet},
};

use crate::{interface::IfId, ipv6::timer::TimerToken, IOContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterState {
    pub role: Role,
    pub groups: FxHashMap<Ipv6Addr, GroupState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Querier,
    NonQuerier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterEvent {
    GeneralQueryTimerExpired(TimerToken),
    QueryFromLowerIpReceived(Ipv6Addr),
    OtherQueriesPresentTimerExpired(TimerToken),
    GroupEvent(Ipv6Addr, GroupEvent),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterAction {
    // Querier relevant events
    StartGeneralQueryTimer(SimTime),
    StartOtherQuerierTimer(SimTime),
    SendGeneralQuery,
    GroupAction(Ipv6Addr, GroupAction),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum GroupState {
    #[default]
    NoListenersPresent,
    ListenersPresent,
    CheckingListeners,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEvent {
    ReportRecevied,
    DoneReceived,
    SpecificQueryReceived,
    TimerExpired(TimerToken),
    RetransmitTimerExpired(TimerToken),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAction {
    StartTimer(SimTime),
    StartRetransmitTimer(SimTime),
    StopRetransmitTimer,
    SendSpecificQuery,
}

const QUERY_INTERVAL: Duration = Duration::from_secs(125);
const QUERY_RESPONSE_INTERVAL: Duration = Duration::from_secs(1);

impl RouterState {
    pub fn on(
        &mut self,
        event: RouterEvent,
        mut f: impl FnMut(RouterAction) -> io::Result<()>,
    ) -> io::Result<()> {
        match event {
            RouterEvent::GeneralQueryTimerExpired(_) => match self.role {
                Role::Querier => {
                    f(RouterAction::SendGeneralQuery)?;
                    f(RouterAction::StartGeneralQueryTimer(
                        SimTime::now() + QUERY_INTERVAL,
                    ))
                }
                Role::NonQuerier => Ok(()),
            },
            RouterEvent::QueryFromLowerIpReceived(_) => match self.role {
                Role::Querier => {
                    self.role = Role::NonQuerier;
                    f(RouterAction::SendGeneralQuery)?;
                    f(RouterAction::StartOtherQuerierTimer(
                        SimTime::now() + QUERY_INTERVAL * 2,
                    ))
                }
                Role::NonQuerier => f(RouterAction::StartOtherQuerierTimer(
                    SimTime::now() + QUERY_INTERVAL * 2,
                )),
            },
            RouterEvent::OtherQueriesPresentTimerExpired(_) => {
                assert_eq!(self.role, Role::NonQuerier);
                self.role = Role::Querier;
                f(RouterAction::SendGeneralQuery)?;
                f(RouterAction::StartOtherQuerierTimer(
                    SimTime::now() + 8 * QUERY_INTERVAL,
                ))
            }
            RouterEvent::GroupEvent(addr, event) => {
                let state = self.groups.entry(addr).or_default();
                state.on(self.role, event, |ga| {
                    f(RouterAction::GroupAction(addr, ga))
                })
            }
        }
    }
}

impl GroupState {
    pub fn on(
        &mut self,
        role: Role,
        event: GroupEvent,
        mut f: impl FnMut(GroupAction) -> io::Result<()>,
    ) -> io::Result<()> {
        match *self {
            // no listernes are known, default case
            GroupState::NoListenersPresent => match event {
                GroupEvent::ReportRecevied => {
                    // Notify routing
                    *self = GroupState::ListenersPresent;
                    f(GroupAction::StartTimer(SimTime::now() + QUERY_INTERVAL))
                }
                _ => Ok(()),
            },
            // we have received a report, and are routing mc traffic
            GroupState::ListenersPresent => match event {
                GroupEvent::ReportRecevied => {
                    f(GroupAction::StartTimer(SimTime::now() + QUERY_INTERVAL))
                }
                GroupEvent::TimerExpired(_) => {
                    // Notify routing
                    *self = GroupState::NoListenersPresent;
                    Ok(())
                }
                GroupEvent::DoneReceived => {
                    // Notify routing
                    f(GroupAction::StartTimer(SimTime::now() + QUERY_INTERVAL))?;
                    if let Role::Querier = role {
                        f(GroupAction::StartRetransmitTimer(
                            SimTime::now() + QUERY_INTERVAL,
                        ))?;
                        f(GroupAction::SendSpecificQuery)?;
                    }
                    Ok(())
                }
                _ => Ok(()),
            },
            // we have recev a DONE, but maybe more readers remain
            GroupState::CheckingListeners => match event {
                GroupEvent::ReportRecevied => {
                    *self = GroupState::ListenersPresent;
                    if let Role::Querier = role {
                        f(GroupAction::StopRetransmitTimer)?;
                    }
                    f(GroupAction::StartTimer(SimTime::now() + QUERY_INTERVAL))
                }
                GroupEvent::RetransmitTimerExpired(_) if role == Role::Querier => {
                    f(GroupAction::SendSpecificQuery)?;
                    f(GroupAction::StartRetransmitTimer(
                        SimTime::now() + QUERY_INTERVAL,
                    ))
                }
                GroupEvent::TimerExpired(_) => {
                    // notify routing
                    *self = GroupState::NoListenersPresent;
                    if let Role::Querier = role {
                        f(GroupAction::StopRetransmitTimer)?;
                    }
                    Ok(())
                }
                _ => Ok(()),
            },
        }
    }
}

impl IOContext {
    pub fn mld_querier_on_event(&mut self, ifid: IfId, event: RouterEvent) -> io::Result<()> {
        let ctrl = self.ipv6.mld.entry(ifid).or_default();
        let Some(mut state) = ctrl.querier.take() else {
            return Ok(());
        };

        state.on(event, |action| match action {
            RouterAction::StartGeneralQueryTimer(deadline) => {
                let token = TimerToken::MulticastListenerDiscoveryGeneralQuery { ifid };
                self.ipv6.timer.reschedule(&token, deadline);
                Ok(())
            }
            RouterAction::StartOtherQuerierTimer(deadline) => {
                let token = TimerToken::MulticastListenerDiscoveryOtherQuerierPresent { ifid };
                self.ipv6.timer.reschedule(&token, deadline);
                Ok(())
            }

            RouterAction::SendGeneralQuery => {
                tracing::info!("sending general query");
                self.ivp6_icmp_send_mld_query(ifid, None)
            }
            RouterAction::GroupAction(addr, action) => match action {
                GroupAction::SendSpecificQuery => {
                    tracing::info!("sending specific query");
                    self.ivp6_icmp_send_mld_query(ifid, Some(addr))
                }
                GroupAction::StartTimer(deadline) => {
                    let token =
                        TimerToken::MulticastListenerDiscoveryQuerierGroupTimer { ifid, addr };
                    self.ipv6.timer.reschedule(&token, deadline);
                    Ok(())
                }
                GroupAction::StartRetransmitTimer(deadline) => {
                    let token =
                        TimerToken::MulticastListenerDiscoveryQuerierGroupRetransmissionTimer {
                            ifid,
                            addr,
                        };
                    self.ipv6.timer.reschedule(&token, deadline);
                    Ok(())
                }
                GroupAction::StopRetransmitTimer => {
                    let token =
                        TimerToken::MulticastListenerDiscoveryQuerierGroupRetransmissionTimer {
                            ifid,
                            addr,
                        };
                    self.ipv6.timer.cancel(&token);
                    Ok(())
                }
            },
        })?;

        self.ipv6.mld.entry(ifid).or_default().querier = Some(state);
        Ok(())
    }

    pub fn designate_ipv6_mld_querier(&mut self, ifid: IfId) -> io::Result<()> {
        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface not found",
            ));
        };

        let _guard = tracing::span!(Level::INFO, "iface", id=%ifid).entered();

        iface.bindings.v6.recv_all_multicast = true;

        let ctrl = self.ipv6.mld.entry(ifid).or_default();
        assert!(ctrl.querier.is_none(), "cannot double designated");

        ctrl.querier = Some(RouterState {
            role: Role::Querier,
            groups: FxHashMap::with_hasher(FxBuildHasher::default()),
        });

        let token = TimerToken::MulticastListenerDiscoveryGeneralQuery { ifid };
        let deadline = SimTime::now() + QUERY_INTERVAL;

        tracing::info!("starting timer {deadline}");
        self.ipv6.timer.schedule(token, deadline);

        tracing::info!("sending general query");
        self.ivp6_icmp_send_mld_query(ifid, None)?;

        Ok(())
    }

    pub(super) fn ivp6_icmp_send_mld_query(
        &mut self,
        ifid: IfId,
        multicast_addr: Option<Ipv6Addr>,
    ) -> io::Result<()> {
        // let ctrl = self.ipv6.mld.entry(ifid).or_default();
        // if ctrl.role != Role::Querier {
        //     return Err(io::Error::new(
        //         io::ErrorKind::InvalidInput,
        //         "interface not configured as MLD querier",
        //     ));
        // }

        let Some(iface) = self.ifaces.get(&ifid) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            ));
        };

        // For each attached link, a router selects one of its link-local
        // unicast addresses on that link to be used as the IPv6 Source Address
        // in all MLD packets it transmits on that link.
        let src = iface
            .bindings
            .v6
            .unicast
            .iter()
            .find(|b| b.addr.scope() == Ipv6AddrScope::UnicastLinkLocal)
            .expect("must have a ll addr")
            .addr;

        // A Querier for a link periodically [Query Interval] sends a General
        // Query on that link, to solicit reports of all multicast addresses of
        // interest on that link.
        let query = match multicast_addr {
            None => IcmpV6MulticastListenerMessage {
                maximum_response_delay: QUERY_RESPONSE_INTERVAL,
                multicast_addr: Ipv6Addr::UNSPECIFIED,
            },
            Some(multicast) => IcmpV6MulticastListenerMessage {
                maximum_response_delay: QUERY_RESPONSE_INTERVAL,
                multicast_addr: multicast,
            },
        };

        // General Queries are sent to the link-scope all-nodes multicast
        // address (FF02::1), with a Multicast Address field of 0, and a Maximum
        // Response Delay of [Query Response Interval].

        let icmp = IcmpV6Packet::MulticastListenerQuery(query);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            next_header: PROTO_ICMPV6,
            hop_limit: 64,
            src,
            dst: Ipv6Addr::MULTICAST_ALL_NODES,
            content: icmp.write_to_bytes()?,
        };

        self.ipv6_send(pkt, ifid)
    }
}

use bytes_io::ToBytes;
use des::time::SimTime;
use fxhash::{FxBuildHasher, FxHashMap, FxHashSet};
use std::{io, net::Ipv6Addr, time::Duration};
use tracing::Level;
use types::{
    icmpv6::{IcmpV6MulticastListenerMessage, IcmpV6Packet, PROTO_ICMPV6},
    ip::{Ipv6AddrExt, Ipv6AddrScope, Ipv6Packet},
};

use crate::{IOContext, interface::IfId, ipv6::timer::TimerToken};

use super::{
    LAST_LISTENER_QUERY_COUNT, LAST_LISTENER_QUERY_INTERVAL, MULTICAST_LISTENER_INTERVAL,
    OTHER_QUERIES_PRESENT_INTERVAL, QUERY_INTERVAL, QUERY_RESPONSE_INTERVAL,
};

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
    GeneralQueryTimerExpired,
    QueryFromLowerIpReceived(Ipv6Addr),
    OtherQueriesPresentTimerExpired,
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
    TimerExpired,
    RetransmitTimerExpired,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAction {
    StartTimer(SimTime),
    StartTimerOrMin(SimTime),
    StartRetransmitTimer(SimTime),
    StopRetransmitTimer,
    SendSpecificQuery,
}

impl RouterState {
    pub fn groups(&self) -> FxHashSet<Ipv6Addr> {
        self.groups
            .iter()
            .filter(|g| *g.1 != GroupState::NoListenersPresent)
            .map(|v| *v.0)
            .collect()
    }

    pub fn on(
        &mut self,
        event: RouterEvent,
        mut f: impl FnMut(RouterAction) -> io::Result<()>,
    ) -> io::Result<()> {
        match event {
            RouterEvent::GeneralQueryTimerExpired => match self.role {
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
                    f(RouterAction::StartOtherQuerierTimer(
                        SimTime::now() + OTHER_QUERIES_PRESENT_INTERVAL,
                    ))
                }
                Role::NonQuerier => f(RouterAction::StartOtherQuerierTimer(
                    SimTime::now() + OTHER_QUERIES_PRESENT_INTERVAL,
                )),
            },
            RouterEvent::OtherQueriesPresentTimerExpired => {
                assert_eq!(self.role, Role::NonQuerier);
                self.role = Role::Querier;
                tracing::trace!("promote to querier");
                f(RouterAction::SendGeneralQuery)?;
                f(RouterAction::StartGeneralQueryTimer(
                    SimTime::now() + QUERY_INTERVAL,
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
                    tracing::trace!("noticed new multicast group");
                    *self = GroupState::ListenersPresent;
                    f(GroupAction::StartTimer(
                        SimTime::now() + MULTICAST_LISTENER_INTERVAL,
                    ))
                }
                _ => Ok(()),
            },
            // we have received a report, and are routing mc traffic
            GroupState::ListenersPresent => match event {
                GroupEvent::ReportRecevied => f(GroupAction::StartTimer(
                    SimTime::now() + MULTICAST_LISTENER_INTERVAL,
                )),
                GroupEvent::TimerExpired => {
                    // Notify routing
                    *self = GroupState::NoListenersPresent;
                    Ok(())
                }
                GroupEvent::DoneReceived => {
                    // Notify routing
                    *self = GroupState::CheckingListeners;
                    f(GroupAction::StartTimerOrMin(
                        SimTime::now() + LAST_LISTENER_QUERY_INTERVAL * LAST_LISTENER_QUERY_COUNT,
                    ))?;
                    if let Role::Querier = role {
                        f(GroupAction::StartRetransmitTimer(
                            SimTime::now() + LAST_LISTENER_QUERY_INTERVAL,
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
                    f(GroupAction::StartTimer(
                        SimTime::now() + MULTICAST_LISTENER_INTERVAL,
                    ))?;
                    if let Role::Querier = role {
                        f(GroupAction::StopRetransmitTimer)?;
                    }
                    Ok(())
                }
                GroupEvent::RetransmitTimerExpired if role == Role::Querier => {
                    f(GroupAction::SendSpecificQuery)?;
                    f(GroupAction::StartRetransmitTimer(
                        SimTime::now() + LAST_LISTENER_QUERY_INTERVAL,
                    ))
                }
                GroupEvent::TimerExpired => {
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
        let Some(ref mut state) = ctrl.querier else {
            return Ok(());
        };

        let _guard = tracing::span!(Level::INFO, "resolver", id=%ifid, ?event).entered();

        let mut actions = Vec::with_capacity(4);
        state.on(event, |action| {
            actions.push(action);
            Ok(())
        })?;

        for action in actions {
            match action {
                RouterAction::StartGeneralQueryTimer(deadline) => {
                    let token = TimerToken::MulticastListenerDiscoveryGeneralQuery { ifid };
                    self.ipv6.timer.reschedule(&token, deadline);
                }
                RouterAction::StartOtherQuerierTimer(deadline) => {
                    let token = TimerToken::MulticastListenerDiscoveryOtherQuerierPresent { ifid };
                    self.ipv6.timer.reschedule(&token, deadline);
                }

                RouterAction::SendGeneralQuery => {
                    self.ivp6_icmp_send_mld_query(ifid, None, QUERY_RESPONSE_INTERVAL)?;
                }
                RouterAction::GroupAction(addr, action) => match action {
                    GroupAction::SendSpecificQuery => {
                        self.ivp6_icmp_send_mld_query(
                            ifid,
                            Some(addr),
                            LAST_LISTENER_QUERY_INTERVAL,
                        )?;
                    }
                    GroupAction::StartTimer(deadline) => {
                        let token =
                            TimerToken::MulticastListenerDiscoveryQuerierGroupTimer { ifid, addr };
                        self.ipv6.timer.reschedule(&token, deadline);
                    }
                    GroupAction::StartTimerOrMin(deadline) => {
                        let token =
                            TimerToken::MulticastListenerDiscoveryQuerierGroupTimer { ifid, addr };
                        let deadline = self
                            .ipv6
                            .timer
                            .active(&token)
                            .map_or(deadline, |d| d.min(deadline));
                        self.ipv6.timer.reschedule(&token, deadline);
                    }

                    GroupAction::StartRetransmitTimer(deadline) => {
                        let token =
                            TimerToken::MulticastListenerDiscoveryQuerierGroupRetransmissionTimer {
                                ifid,
                                addr,
                            };
                        self.ipv6.timer.reschedule(&token, deadline);
                    }
                    GroupAction::StopRetransmitTimer => {
                        let token =
                            TimerToken::MulticastListenerDiscoveryQuerierGroupRetransmissionTimer {
                                ifid,
                                addr,
                            };
                        self.ipv6.timer.cancel(&token);
                    }
                },
            }
        }

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

        self.ipv6.timer.schedule(token, deadline);
        self.ivp6_icmp_send_mld_query(ifid, None, QUERY_RESPONSE_INTERVAL)?; // STARTUP INTERVAL

        Ok(())
    }

    pub fn undesignate_ipv6_mld_querier(&mut self, ifid: IfId) -> io::Result<()> {
        let Some(iface) = self.ifaces.get_mut(&ifid) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface not found",
            ));
        };

        let _guard = tracing::span!(Level::INFO, "iface", id=%ifid).entered();
        iface.bindings.v6.recv_all_multicast = false;

        let ctrl = self.ipv6.mld.entry(ifid).or_default();
        ctrl.querier = None;

        Ok(())
    }

    pub(super) fn ipv6_icmp_mld_src_addr(&self, ifid: IfId) -> io::Result<Ipv6Addr> {
        let Some(iface) = self.ifaces.get(&ifid) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            ));
        };

        iface
            .bindings
            .v6
            .unicast
            .iter()
            .find(|b| b.addr.scope() == Ipv6AddrScope::UnicastLinkLocal)
            .map(|b| b.addr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no link-local address found"))
    }

    pub(super) fn ivp6_icmp_send_mld_query(
        &mut self,
        ifid: IfId,
        multicast_addr: Option<Ipv6Addr>,
        maximum_response_delay: Duration,
    ) -> io::Result<()> {
        // For each attached link, a router selects one of its link-local
        // unicast addresses on that link to be used as the IPv6 Source Address
        // in all MLD packets it transmits on that link.
        let src = self.ipv6_icmp_mld_src_addr(ifid)?;

        // A Querier for a link periodically [Query Interval] sends a General
        // Query on that link, to solicit reports of all multicast addresses of
        // interest on that link.
        let query = IcmpV6MulticastListenerMessage {
            maximum_response_delay,
            multicast_addr: multicast_addr.unwrap_or(Ipv6Addr::UNSPECIFIED),
        };

        if self.ipv6.mld.entry(ifid).or_default().querier.is_some() {
            self.ipv6_icmp_recv_multicast_listener_query(src, ifid, query.clone())?;
        }

        // General Queries are sent to the link-scope all-nodes multicast
        // address (FF02::1), with a Multicast Address field of 0, and a Maximum
        // Response Delay of [Query Response Interval].
        let icmp = IcmpV6Packet::MulticastListenerQuery(query);
        let pkt = Ipv6Packet {
            traffic_class: 0,
            flow_label: 0,
            proto: PROTO_ICMPV6,
            hop_limit: 64,
            extension_headers: Vec::new(),
            src,
            dst: Ipv6Addr::MULTICAST_ALL_NODES,
            content: icmp.write_to_bytes()?,
        };

        self.ipv6_send(pkt, Some(ifid))
    }
}

#[cfg(test)]
mod tests {
    use des::runtime::{Application, Builder, EventLifecycle, RuntimeError};
    use serial_test::serial;

    use super::*;

    fn rng_sim(f: impl FnOnce() -> io::Result<()>) -> Result<(), RuntimeError> {
        struct App<F: FnOnce() -> io::Result<()>>(Option<F>);
        impl<F: FnOnce() -> io::Result<()>> Application for App<F> {
            type EventSet = ();
            type Lifecycle = Self;
        }
        impl<F: FnOnce() -> io::Result<()>> EventLifecycle for App<F> {
            fn at_sim_end(runtime: &mut des::prelude::Runtime<Self>) -> Result<(), RuntimeError>
            where
                Self: Application,
            {
                (runtime.app.0.take().unwrap())()?;
                Ok(())
            }
        }

        Builder::seeded(123).build(App(Some(f))).run().map(|_| ())
    }

    // Router Actions

    #[test]
    #[serial]
    fn on_gen_query_expired_for_querier() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = RouterState {
                role: Role::Querier,
                groups: FxHashMap::default(),
            };
            let mut actions = Vec::new();
            state.on(RouterEvent::GeneralQueryTimerExpired, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 2);
            assert!(matches!(actions[0], RouterAction::SendGeneralQuery));
            assert!(matches!(
                actions[1],
                RouterAction::StartGeneralQueryTimer(_)
            ));
            assert_eq!(state.role, Role::Querier);

            Ok(())
        })
    }

    #[test]
    #[serial]
    fn on_lower_ip_query_for_querier() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = RouterState {
                role: Role::Querier,
                groups: FxHashMap::default(),
            };
            let mut actions = Vec::new();
            state.on(
                RouterEvent::QueryFromLowerIpReceived(Ipv6Addr::UNSPECIFIED),
                |action| {
                    actions.push(action);
                    Ok(())
                },
            )?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(
                actions[0],
                RouterAction::StartOtherQuerierTimer(_)
            ));
            assert_eq!(state.role, Role::NonQuerier);

            Ok(())
        })
    }

    #[test]
    #[serial]
    fn on_lower_ip_query_for_non_querier() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = RouterState {
                role: Role::NonQuerier,
                groups: FxHashMap::default(),
            };
            let mut actions = Vec::new();
            state.on(
                RouterEvent::QueryFromLowerIpReceived(Ipv6Addr::UNSPECIFIED),
                |action| {
                    actions.push(action);
                    Ok(())
                },
            )?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(
                actions[0],
                RouterAction::StartOtherQuerierTimer(_)
            ));
            assert_eq!(state.role, Role::NonQuerier);

            Ok(())
        })
    }

    #[test]
    #[serial]
    fn on_other_querier_expired_for_non_querier() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = RouterState {
                role: Role::NonQuerier,
                groups: FxHashMap::default(),
            };
            let mut actions = Vec::new();
            state.on(RouterEvent::OtherQueriesPresentTimerExpired, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 2);
            assert!(matches!(actions[0], RouterAction::SendGeneralQuery));
            assert!(matches!(
                actions[1],
                RouterAction::StartGeneralQueryTimer(_)
            ));
            assert_eq!(state.role, Role::Querier);

            Ok(())
        })
    }

    // Group Actions

    #[test]
    #[serial]
    fn group_no_listeners_on_report() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = GroupState::NoListenersPresent;
            let mut actions = Vec::new();
            state.on(Role::Querier, GroupEvent::ReportRecevied, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], GroupAction::StartTimer(_)));
            assert_eq!(state, GroupState::ListenersPresent);
            Ok(())
        })
    }

    #[test]
    #[serial]
    fn group_listeners_on_report() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = GroupState::ListenersPresent;
            let mut actions = Vec::new();
            state.on(Role::Querier, GroupEvent::ReportRecevied, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], GroupAction::StartTimer(_)));
            assert_eq!(state, GroupState::ListenersPresent);
            Ok(())
        })
    }

    #[test]
    #[serial]
    fn group_listeners_on_timer_expired() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = GroupState::ListenersPresent;
            let mut actions = Vec::new();
            state.on(Role::Querier, GroupEvent::TimerExpired, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 0);
            assert_eq!(state, GroupState::NoListenersPresent);
            Ok(())
        })
    }

    #[test]
    #[serial]
    fn group_listeners_on_done() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = GroupState::ListenersPresent;
            let mut actions = Vec::new();
            state.on(Role::Querier, GroupEvent::DoneReceived, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 3);
            assert!(matches!(actions[0], GroupAction::StartTimerOrMin(_),),);
            assert!(matches!(actions[1], GroupAction::StartRetransmitTimer(_)));
            assert!(matches!(actions[2], GroupAction::SendSpecificQuery));
            assert_eq!(state, GroupState::CheckingListeners);

            // Non Querier

            let mut state = GroupState::ListenersPresent;
            let mut actions = Vec::new();
            state.on(Role::NonQuerier, GroupEvent::DoneReceived, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], GroupAction::StartTimerOrMin(_)));
            assert_eq!(state, GroupState::CheckingListeners);
            Ok(())
        })
    }

    #[test]
    #[serial]
    fn group_checking_on_report() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = GroupState::CheckingListeners;
            let mut actions = Vec::new();
            state.on(Role::Querier, GroupEvent::ReportRecevied, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 2);
            assert!(matches!(actions[0], GroupAction::StartTimer(_)));
            assert!(matches!(actions[1], GroupAction::StopRetransmitTimer));
            assert_eq!(state, GroupState::ListenersPresent);

            // Non Querier

            let mut state = GroupState::CheckingListeners;
            let mut actions = Vec::new();
            state.on(Role::NonQuerier, GroupEvent::ReportRecevied, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], GroupAction::StartTimer(_)));
            assert_eq!(state, GroupState::ListenersPresent);
            Ok(())
        })
    }

    #[test]
    #[serial]
    fn group_checking_on_retransmit_expired() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = GroupState::CheckingListeners;
            let mut actions = Vec::new();
            state.on(
                Role::Querier,
                GroupEvent::RetransmitTimerExpired,
                |action| {
                    actions.push(action);
                    Ok(())
                },
            )?;

            assert_eq!(actions.len(), 2);
            assert!(matches!(actions[0], GroupAction::SendSpecificQuery));
            assert!(matches!(actions[1], GroupAction::StartRetransmitTimer(_)));
            assert_eq!(state, GroupState::CheckingListeners);

            // Non Querier

            let mut state = GroupState::CheckingListeners;
            let mut actions = Vec::new();
            state.on(
                Role::NonQuerier,
                GroupEvent::RetransmitTimerExpired,
                |action| {
                    actions.push(action);
                    Ok(())
                },
            )?;

            assert_eq!(actions.len(), 0);
            assert_eq!(state, GroupState::CheckingListeners);
            Ok(())
        })
    }

    #[test]
    #[serial]
    fn group_checking_on_timer_expired() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = GroupState::CheckingListeners;
            let mut actions = Vec::new();
            state.on(Role::Querier, GroupEvent::TimerExpired, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], GroupAction::StopRetransmitTimer));
            assert_eq!(state, GroupState::NoListenersPresent);

            // Non Querier

            let mut state = GroupState::CheckingListeners;
            let mut actions = Vec::new();
            state.on(Role::NonQuerier, GroupEvent::TimerExpired, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 0);
            assert_eq!(state, GroupState::NoListenersPresent);
            Ok(())
        })
    }
}

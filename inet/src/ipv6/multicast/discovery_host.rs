//! Multicast listener discovery
//!
//! The purpose of Multicast Listener Discovery (MLD) is to enable each
//! IPv6 router to discover the presence of multicast listeners (that is,
//! nodes wishing to receive multicast packets) on its directly attached
//! links, and to discover specifically which multicast addresses are of
//! interest to those neighboring nodes.  This information is then
//! provided to whichever multicast routing protocol is being used by the
//! router, in order to ensure that multicast packets are delivered to
//! all links where there are interested receivers.
//!
//! MLD is an asymmetric protocol, specifying different behaviors for
//! multicast listeners and for routers.  For those multicast addresses
//! to which a router itself is listening, the router performs both parts
//! of the protocol, including responding to its own messages.

use std::{io, net::Ipv6Addr, time::Duration};

use bytes_io::ToBytes;
use des::time::SimTime;
use tracing::Level;
use types::{
    icmpv6::{IcmpV6MulticastListenerMessage, IcmpV6Packet, PROTO_ICMPV6},
    ip::Ipv6Packet,
};

use crate::{
    ctx::IOContext,
    interface::IfId,
    ipv6::{timer::TimerToken, Ipv6SendFlags},
};

const DEFAULT_UNSOLICITD_MAX_RESPONSE_DELAY: Duration = Duration::from_millis(500);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    #[default]
    NonListener,
    IdleListener(bool),
    DelayedListener(bool, SimTime),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    StartListening,
    StopListening,
    QueryReceived(IcmpV6MulticastListenerMessage),
    ReportReceived(IcmpV6MulticastListenerMessage),
    TimerExpired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeAction {
    SendReport,
    SendDone,
    StartTimer(SimTime),
    ResetTimer(SimTime),
    StopTimer,
}

impl NodeState {
    fn on(
        self,
        event: NodeEvent,
        mut f: impl FnMut(NodeAction) -> io::Result<()>,
    ) -> io::Result<NodeState> {
        match self {
            NodeState::NonListener => match event {
                NodeEvent::StartListening => {
                    f(NodeAction::SendReport)?;
                    let deadline = SimTime::now()
                        + Duration::from_secs_f64(
                            DEFAULT_UNSOLICITD_MAX_RESPONSE_DELAY.as_secs_f64()
                                + des::runtime::random::<f64>(),
                        );
                    f(NodeAction::StartTimer(deadline))?;
                    Ok(NodeState::DelayedListener(true, deadline))
                }
                _ => Ok(self),
            },
            NodeState::DelayedListener(flag, timer_state) => match event {
                NodeEvent::StopListening => {
                    f(NodeAction::StopTimer)?;
                    if flag {
                        f(NodeAction::SendDone)?;
                    }
                    Ok(NodeState::NonListener)
                }
                NodeEvent::QueryReceived(query) => {
                    // If max response delay < shrink timer
                    if SimTime::now() + query.maximum_response_delay < timer_state {
                        let new_deadline = SimTime::now()
                            + Duration::from_secs_f64(
                                query.maximum_response_delay.as_secs_f64()
                                    * des::runtime::random::<f64>(),
                            );
                        f(NodeAction::ResetTimer(new_deadline))?;
                    }
                    Ok(self)
                }
                NodeEvent::TimerExpired => {
                    f(NodeAction::SendReport)?;
                    Ok(NodeState::IdleListener(true))
                }
                NodeEvent::ReportReceived(_report) => {
                    f(NodeAction::StopTimer)?;
                    Ok(NodeState::IdleListener(false))
                }
                _ => Ok(self),
            },
            NodeState::IdleListener(flag) => match event {
                NodeEvent::QueryReceived(query) => {
                    let deadline = SimTime::now()
                        + Duration::from_secs_f64(
                            query.maximum_response_delay.as_secs_f64()
                                * des::runtime::random::<f64>(),
                        );
                    f(NodeAction::StartTimer(deadline))?;
                    Ok(NodeState::DelayedListener(flag, deadline))
                }
                NodeEvent::StopListening => {
                    if flag {
                        f(NodeAction::SendDone)?;
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
        event: NodeEvent,
        multicast_addr: Ipv6Addr,
    ) -> io::Result<()> {
        let _guard = tracing::span!(Level::INFO, "group", addr=%multicast_addr, ?event).entered();

        let ctrl = self.ipv6.mld.entry(ifid).or_default();
        let state = *ctrl
            .group_memberships
            .get(&multicast_addr)
            .unwrap_or(&NodeState::default());

        let new_state = state.on(event, |action| match action {
            NodeAction::SendReport => {
                tracing::info!("send report");
                self.ipv6_icmp_send_mld_report(ifid, multicast_addr)
            }
            NodeAction::SendDone => {
                tracing::info!("send done");
                self.ipv6_icmp_send_mld_done(ifid, multicast_addr)
            }
            NodeAction::StartTimer(deadline) => {
                tracing::info!("start timer {deadline}");
                let token = TimerToken::MulticastListenerDiscoverySendReport {
                    ifid,
                    multicast_addr,
                };
                self.ipv6.timer.schedule(token, deadline);
                Ok(())
            }
            NodeAction::ResetTimer(new_deadline) => {
                tracing::info!("reset timer");
                let token = TimerToken::MulticastListenerDiscoverySendReport {
                    ifid,
                    multicast_addr,
                };
                self.ipv6.timer.reschedule(&token, new_deadline);
                Ok(())
            }
            NodeAction::StopTimer => {
                tracing::info!("stop timer");
                let token = TimerToken::MulticastListenerDiscoverySendReport {
                    ifid,
                    multicast_addr,
                };
                self.ipv6.timer.cancel(&token);
                Ok(())
            }
        })?;

        let ctrl = self.ipv6.mld.entry(ifid).or_default();
        ctrl.group_memberships.insert(multicast_addr, new_state);

        Ok(())
    }

    pub(super) fn ipv6_icmp_send_mld_report(
        &mut self,
        ifid: IfId,
        multicast: Ipv6Addr,
    ) -> io::Result<()> {
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
            hop_limit: 2,
            src: Ipv6Addr::UNSPECIFIED,
            dst: multicast,
            content: msg.write_to_bytes()?,
        };

        // TODO: this should ?? always use fe80 addrs, but what to do when no such addr is availabel ??
        self.ipv6_send_with_flags(pkt, ifid, Ipv6SendFlags::ALLOW_SRC_UNSPECIFIED)?;

        Ok(())
    }

    pub(super) fn ipv6_icmp_send_mld_done(
        &mut self,
        ifid: IfId,
        multicast_addr: Ipv6Addr,
    ) -> io::Result<()> {
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
            content: msg.write_to_bytes()?,
        };

        // TODO: this should ?? always use fe80 addrs, but what to do when no such addr is availabel ??
        self.ipv6_send_with_flags(pkt, ifid, Ipv6SendFlags::ALLOW_SRC_UNSPECIFIED)
    }
}

#[cfg(test)]
mod tests {
    use des::runtime::{Application, Builder, EventLifecycle, RuntimeError};

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

    #[test]
    fn on_start_listening_new() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = NodeState::NonListener;
            let mut actions = Vec::new();
            state = state.on(NodeEvent::StartListening, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 2);
            assert!(matches!(actions[0], NodeAction::SendReport));
            assert!(matches!(actions[1], NodeAction::StartTimer(_)));
            assert!(matches!(state, NodeState::DelayedListener(true, _)));

            Ok(())
        })
    }

    #[test]
    fn on_stop_delayed_listener() -> Result<(), RuntimeError> {
        rng_sim(|| {
            // NO FLAG
            let mut state = NodeState::DelayedListener(false, 100.0.into());
            let mut actions = Vec::new();
            state = state.on(NodeEvent::StopListening, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], NodeAction::StopTimer));
            assert!(matches!(state, NodeState::NonListener));

            // FLAG SET
            let mut state = NodeState::DelayedListener(true, 100.0.into());
            let mut actions = Vec::new();
            state = state.on(NodeEvent::StopListening, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 2);
            assert!(matches!(actions[0], NodeAction::StopTimer));
            assert!(matches!(actions[1], NodeAction::SendDone));
            assert!(matches!(state, NodeState::NonListener));

            Ok(())
        })
    }

    #[test]
    fn on_stop_idle_listener() -> Result<(), RuntimeError> {
        rng_sim(|| {
            // NO FLAG
            let mut state = NodeState::IdleListener(false);
            let mut actions = Vec::new();
            state = state.on(NodeEvent::StopListening, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 0);
            assert!(matches!(state, NodeState::NonListener));

            // FLAG SET
            let mut state = NodeState::IdleListener(true);
            let mut actions = Vec::new();
            state = state.on(NodeEvent::StopListening, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], NodeAction::SendDone));
            assert!(matches!(state, NodeState::NonListener));

            Ok(())
        })
    }

    #[test]
    fn on_query_delayed_listener() -> Result<(), RuntimeError> {
        rng_sim(|| {
            // Max resp time < current time
            let mut state = NodeState::DelayedListener(false, 11.0.into());
            let mut actions = Vec::new();
            state = state.on(
                NodeEvent::QueryReceived(IcmpV6MulticastListenerMessage {
                    maximum_response_delay: Duration::from_secs(10),
                    multicast_addr: Ipv6Addr::UNSPECIFIED,
                }),
                |action| {
                    actions.push(action);
                    Ok(())
                },
            )?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], NodeAction::ResetTimer(_)));
            assert!(matches!(state, NodeState::DelayedListener(false, _)));

            // Max resp time >= current time
            let mut state = NodeState::DelayedListener(false, 8.0.into());
            let mut actions = Vec::new();
            state = state.on(
                NodeEvent::QueryReceived(IcmpV6MulticastListenerMessage {
                    maximum_response_delay: Duration::from_secs(10),
                    multicast_addr: Ipv6Addr::UNSPECIFIED,
                }),
                |action| {
                    actions.push(action);
                    Ok(())
                },
            )?;

            assert_eq!(actions.len(), 0);
            assert!(matches!(state, NodeState::DelayedListener(false, _)));

            Ok(())
        })
    }

    #[test]
    fn on_query_idle_listener() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = NodeState::IdleListener(true);
            let mut actions = Vec::new();
            state = state.on(
                NodeEvent::QueryReceived(IcmpV6MulticastListenerMessage {
                    maximum_response_delay: Duration::from_secs(10),
                    multicast_addr: Ipv6Addr::UNSPECIFIED,
                }),
                |action| {
                    actions.push(action);
                    Ok(())
                },
            )?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], NodeAction::StartTimer(_)));
            assert!(matches!(state, NodeState::DelayedListener(true, _)));

            Ok(())
        })
    }

    #[test]
    fn on_report_delayed_listener() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = NodeState::DelayedListener(true, 100.0.into());
            let mut actions = Vec::new();
            state = state.on(
                NodeEvent::ReportReceived(IcmpV6MulticastListenerMessage {
                    maximum_response_delay: Duration::from_secs(10),
                    multicast_addr: Ipv6Addr::UNSPECIFIED,
                }),
                |action| {
                    actions.push(action);
                    Ok(())
                },
            )?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], NodeAction::StopTimer));
            assert!(matches!(state, NodeState::IdleListener(false)));

            Ok(())
        })
    }

    #[test]
    fn on_report_timeout() -> Result<(), RuntimeError> {
        rng_sim(|| {
            let mut state = NodeState::DelayedListener(true, 100.0.into());
            let mut actions = Vec::new();
            state = state.on(NodeEvent::TimerExpired, |action| {
                actions.push(action);
                Ok(())
            })?;

            assert_eq!(actions.len(), 1);
            assert!(matches!(actions[0], NodeAction::SendReport));
            assert!(matches!(state, NodeState::IdleListener(true)));

            Ok(())
        })
    }
}

use des::runtime::RuntimeError;
use serial_test::serial;

use crate::{ioctx, utils::SimpleSim};

use super::*;
use std::net::Ipv4Addr;

type ResultDyn = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
#[serial]
fn edit_policy_table() -> Result<(), RuntimeError> {
    let mut sim = SimpleSim::default();
    sim.v6 = true;
    sim.node("alice", || async move {
        super::policy_reset()?;

        ioctx().do_io(|ctx| {
            assert_eq!(ctx.ipv6.policies.table.len(), 9);
        });

        super::policy_add("2003:a:1::1234/64".parse().unwrap(), 100, 1)?;
        super::policy_add("2003:a:2::1234/64".parse().unwrap(), 100, 1)?;
        super::policy_add("2003:a:3::1234/64".parse().unwrap(), 100, 1)?;

        ioctx().do_io(|ctx| {
            assert_eq!(ctx.ipv6.policies.table.len(), 12);
            assert_eq!(
                ctx.ipv6.policies.lookup("2003:a:2::1234".parse().unwrap()),
                Some(&PolicyEntry {
                    precedence: 100,
                    label: 1
                })
            );
        });

        super::policy_remove("2003:a:2::1234/64".parse().unwrap())?;

        ioctx().do_io(|ctx| {
            assert_eq!(ctx.ipv6.policies.table.len(), 11);
            assert_eq!(
                ctx.ipv6.policies.lookup("2003:a:2::1234".parse().unwrap()),
                Some(&PolicyEntry {
                    // other entry UNSPECIFIED -> 40 catches by default
                    precedence: 40,
                    label: 1
                })
            );
        });

        Ok(())
    });
    sim.run()
}

#[test]
fn src_addr_selection_appropiate_scope() -> ResultDyn {
    let table = PolicyTable::default();

    let set = SrcAddrCanidateSet {
        dst: "2001:db8:1::1".parse()?,
        ifid: IfId::new("eth0").into(),
        addrs: vec!["2001:db8:3::1 #eth0".parse()?, ("fe80::1 #eth0".parse()?)],
    };
    assert_eq!(set.select(&table), Some("2001:db8:3::1 #eth0".parse()?));

    let set = SrcAddrCanidateSet {
        dst: "ff05::1".parse()?,
        ifid: IfId::new("eth0").into(),
        addrs: vec![("2001:db8:3::1 #eth0".parse()?), ("fe80::1 #eth0".parse()?)],
    };
    assert_eq!(set.select(&table), Some("2001:db8:3::1 #eth0".parse()?));

    let set = SrcAddrCanidateSet {
        dst: "fe80::1".parse()?,
        ifid: IfId::new("eth0").into(),
        addrs: vec![("fe80::2 #eth0".parse()?), ("2001:db8:1::1 #eth0".parse()?)],
    };
    assert_eq!(set.select(&table), Some("fe80::2 #eth0".parse()?));

    Ok(())
}

#[test]
fn src_addr_selection_same_addr() -> ResultDyn {
    let table = PolicyTable::default();

    let set = SrcAddrCanidateSet {
        dst: "2001:db8:1::1".parse()?,
        ifid: IfId::new("eth0").into(),
        addrs: vec![
            ("2001:db8:1::1 #eth0".parse()?),
            ("2001:db8:2::1 #eth0".parse()?),
        ],
    };
    assert_eq!(set.select(&table), Some("2001:db8:1::1 #eth0".parse()?));

    Ok(())
}

#[test]
fn src_addr_selection_longest_prefix_match() -> ResultDyn {
    let table = PolicyTable::default();

    let set = SrcAddrCanidateSet {
        dst: "2001:db8:1::1".parse()?,
        ifid: IfId::new("eth0").into(),
        addrs: vec![
            ("2001:db8:1::2 #eth0".parse()?),
            ("2001:db8:3::2 #eth0".parse()?),
        ],
    };
    assert_eq!(set.select(&table), Some("2001:db8:1::2 #eth0".parse()?));

    Ok(())
}

#[test]
fn src_addr_selection_matching_label() -> ResultDyn {
    let table = PolicyTable::default();

    let set = SrcAddrCanidateSet {
        dst: "2002:c633:6401::1".parse()?,
        ifid: IfId::new("eth0").into(),
        addrs: vec![
            ("2002:c633:6401::d5e3:7953:13eb:22e8 #eth0".parse()?),
            ("2001:db8:1::2 #eth0".parse()?),
        ],
    };
    assert_eq!(
        set.select(&table),
        Some("2002:c633:6401::d5e3:7953:13eb:22e8 #eth0".parse()?)
    );

    Ok(())
}

#[test]
fn src_addr_selection_home_addr() -> ResultDyn {
    let table = PolicyTable::default();

    let set = SrcAddrCanidateSet {
        dst: "2001:db8:1::1".parse()?,
        ifid: IfId::new("eth0").into(),
        addrs: vec![
            ("2001:db8:1::2 #eth0 (care-of-addr)".parse()?),
            ("2001:db8:3::2 #eth0 (care-of-addr) (home-addr)".parse()?),
        ],
    };
    assert_eq!(
        set.select(&table),
        Some("2001:db8:3::2 #eth0 (care-of-addr) (home-addr)".parse()?)
    );

    Ok(())
}

#[test]
fn src_addr_selection_temporary() -> ResultDyn {
    let table = PolicyTable::default();

    let set = SrcAddrCanidateSet {
        dst: "2001:db8:1::d5e3:0:0:1".parse()?,
        ifid: IfId::new("eth0").into(),
        addrs: vec![
            ("2001:db8:1::2 #eth0".parse()?),
            ("2001:db8:1::d5e3:7953:13eb:22e8 #eth0 (temporary)".parse()?),
        ],
    };
    assert_eq!(
        set.select(&table),
        Some("2001:db8:1::d5e3:7953:13eb:22e8 #eth0 (temporary)".parse()?)
    );

    Ok(())
}

#[test]
fn dst_addr_selection_small_scope() -> ResultDyn {
    let table = PolicyTable::default();
    let mut selector = AddrSelection::new_with_static(
        vec!["2001:db8:1::1".parse()?, "fe80::1".parse()?],
        vec![("2001:db8:1::2 #en0".parse()?), ("fe80::2 #en0".parse()?)],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "fe80::1".parse()?,
                src: "fe80::2".parse()?,
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "2001:db8:1::2".parse()?,
                src_ifid: IfId::new("en0"),
            },
        ]
    );
    Ok(())
}

#[test]
fn dst_addr_selection_longest_prefix() -> ResultDyn {
    let table = PolicyTable::default();
    let mut selector = AddrSelection::new_with_static(
        vec!["2001:db8:1::1".parse()?, "2001:db8:3ffe::1".parse()?],
        vec![
            ("2001:db8:1::2 #en0".parse()?),
            ("2001:db8:3f44::2 #en0".parse()?),
            ("fe80::2 #en0".parse()?),
        ],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "2001:db8:1::2".parse()?,
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "2001:db8:3ffe::1".parse()?,
                src: "2001:db8:3f44::2".parse()?,
                src_ifid: IfId::new("en0"),
            }
        ]
    );
    Ok(())
}

#[test]
fn dst_addr_selection_matching_label() -> ResultDyn {
    let table = PolicyTable::default();
    let mut selector = AddrSelection::new_with_static(
        vec!["2002:c633:6401::1".parse()?, "2001:db8:1::1".parse()?],
        vec![
            ("2002:c633:6401::2 #en0".parse()?),
            ("fe80::2 #en0".parse()?),
        ],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "2002:c633:6401::1".parse()?,
                src: "2002:c633:6401::2".parse()?,
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "2002:c633:6401::2".parse()?,
                src_ifid: IfId::new("en0"),
            }
        ]
    );
    Ok(())
}

#[test]
fn dst_addr_selection_precedence() -> ResultDyn {
    let table = PolicyTable::default();
    let mut selector = AddrSelection::new_with_static(
        vec!["2002:c633:6401::1".parse()?, "2001:db8:1::1".parse()?],
        vec![
            ("2002:c633:6401::2 #en0".parse()?),
            ("2001:db8:1::2 #en0".parse()?),
            ("fe80::2 #en0".parse()?),
        ],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "2001:db8:1::2".parse()?,
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "2002:c633:6401::1".parse()?,
                src: "2002:c633:6401::2".parse()?,
                src_ifid: IfId::new("en0"),
            }
        ]
    );

    let mut selector = AddrSelection::new_with_static(
        vec![
            "2001:db8:1::1".parse()?,
            "10.1.2.3".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
        ],
        vec![
            ("2001:db8:1::2 #en0".parse()?),
            ("fe80::1 #en0".parse()?),
            ("10.1.2.4 #en0".parse()?),
        ],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "2001:db8:1::2".parse()?,
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "10.1.2.3".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                src: "10.1.2.4".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                src_ifid: IfId::new("en0"),
            }
        ]
    );
    Ok(())
}

#[test]
fn dst_addr_selection_matching_scope() -> ResultDyn {
    let table = PolicyTable::default();
    let mut selector = AddrSelection::new_with_static(
        vec![
            "2001:db8:1::1".parse()?,
            "198.51.100.121".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
        ],
        vec![
            ("2001:db8:1::2 #en0".parse()?),
            ("fe80::1 #en0".parse()?),
            ("169.254.13.78 #en0".parse()?),
        ],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "2001:db8:1::2".parse()?,
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "198.51.100.121".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                src: "169.254.13.78".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                src_ifid: IfId::new("en0"),
            }
        ]
    );

    let mut selector = AddrSelection::new_with_static(
        vec![
            "2001:db8:1::1".parse()?,
            "198.51.100.121".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
        ],
        vec![("fe80::1 #en0".parse()?), ("198.51.100.117 #en0".parse()?)],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "198.51.100.121".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                src: "198.51.100.117".parse::<Ipv4Addr>()?.to_ipv6_mapped(),
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "fe80::1".parse()?,
                src_ifid: IfId::new("en0"),
            },
        ]
    );
    Ok(())
}

#[test]
fn dst_addr_selection_home_addr() -> ResultDyn {
    let table = PolicyTable::default();
    let mut selector = AddrSelection::new_with_static(
        vec!["2001:db8:1::1".parse()?, "fe80::1".parse()?],
        vec![
            ("2001:db8:1::2 #en0 (care-of-addr)".parse()?),
            ("2001:db8:3::1 #en0 (care-of-addr) (home-addr)".parse()?),
            ("fe80::2 #en0 (care-of-addr)".parse()?),
        ],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "2001:db8:3::1".parse()?,
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "fe80::1".parse()?,
                src: "fe80::2".parse()?,
                src_ifid: IfId::new("en0"),
            }
        ]
    );
    Ok(())
}

#[test]
fn dst_addr_select_avoid_depc() -> ResultDyn {
    let table = PolicyTable::default();
    let mut selector = AddrSelection::new_with_static(
        vec!["2001:db8:1::1".parse()?, "fe80::1".parse()?],
        vec![
            ("2001:db8:1::2 #en0".parse()?),
            ("fe80::2 #en0 (deprecated)".parse()?),
        ],
    );

    assert_eq!(
        selector.select_all(&table),
        [
            Selection {
                dst: "2001:db8:1::1".parse()?,
                src: "2001:db8:1::2".parse()?,
                src_ifid: IfId::new("en0"),
            },
            Selection {
                dst: "fe80::1".parse()?,
                src: "fe80::2".parse()?,
                src_ifid: IfId::new("en0"),
            }
        ]
    );
    Ok(())
}

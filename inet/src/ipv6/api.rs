use std::io;

use crate::{IOHandle, ioctx};

use super::cfg::HostConfiguration;

pub fn set_node_cfg(cfg: HostConfiguration) -> io::Result<()> {
    ioctx().ipv6_set_node_cfg(cfg)
}

pub fn ipv6() {
    ioctx().ipv6_info();
}

impl IOHandle {
    pub fn ipv6_set_node_cfg(&self, cfg: HostConfiguration) -> io::Result<()> {
        self.do_failable(|ctx| {
            ctx.ipv6.cfg = cfg;
            Ok(())
        })
    }

    pub fn ipv6_info(&self) {
        self.do_io(|ctx| {
            tracing::info!("[ Prefix list ]");
            for prefix in &*ctx.ipv6.prefixes {
                tracing::info!(
                    "{}{}",
                    prefix.prefix,
                    prefix
                        .assigned_addr
                        .as_ref()
                        .map(|addr| format!(" assinged {addr}"))
                        .unwrap_or(String::new())
                );
            }

            tracing::info!("[ Destination cache ]");
            for (dst, entry) in &ctx.ipv6.destinations.mapping {
                tracing::info!("{dst} -> {} mtu {}", entry.next_hop, entry.path_mtu);
            }

            tracing::info!("[ Default routers ]");
            for router in &ctx.ipv6.default_routers.list {
                tracing::info!("{}", router.addr);
            }

            tracing::info!("[ Neighbor cache ]");
            for (ip, entry) in &ctx.ipv6.neighbors.mapping {
                tracing::info!("{ip} @ {entry}");
            }
        })
    }
}

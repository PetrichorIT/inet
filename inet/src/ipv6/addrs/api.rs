use std::io;

use types::ip::Ipv6Prefix;

use crate::{IOContext, IOHandle};

use super::PolicyTable;

/// Adds a polciy to the policy table.
pub fn policy_add(prefix: Ipv6Prefix, precedence: usize, label: usize) -> io::Result<()> {
    IOContext::failable_api(|ctx| {
        ctx.ipv6.policies.add(prefix, precedence, label);
        Ok(())
    })
}

/// Removes a polciy from the table.
pub fn policy_remove(prefix: Ipv6Prefix) -> io::Result<()> {
    IOContext::failable_api(|ctx| {
        ctx.ipv6.policies.remove(prefix);
        Ok(())
    })
}

/// Retrusn to the default table state.
pub fn policy_reset() -> io::Result<()> {
    IOContext::failable_api(|ctx| {
        ctx.ipv6.policies = PolicyTable::default();
        Ok(())
    })
}

impl IOHandle {
    pub fn policy_add(
        &self,
        prefix: Ipv6Prefix,
        precedence: usize,
        label: usize,
    ) -> io::Result<()> {
        self.do_failable(|ctx| {
            ctx.ipv6.policies.add(prefix, precedence, label);
            Ok(())
        })
    }

    pub fn policy_remove(&self, prefix: Ipv6Prefix) -> io::Result<()> {
        self.do_failable(|ctx| {
            ctx.ipv6.policies.remove(prefix);
            Ok(())
        })
    }

    pub fn policy_reset(&self) -> io::Result<()> {
        self.do_failable(|ctx| {
            ctx.ipv6.policies = PolicyTable::default();
            Ok(())
        })
    }
}

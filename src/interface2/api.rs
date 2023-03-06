use std::io;

use super::Interface;
use crate::IOContext;

pub fn add_interface2(iface: Interface) -> io::Result<()> {
    IOContext::with_current(|ctx| ctx.add_interface2(iface))
}

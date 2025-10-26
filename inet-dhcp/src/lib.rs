mod packet;
use std::net::Ipv4Addr;

use des::runtime::random;
use inet::types::iface::MacAddress;
pub use packet::*;

impl DhcpPacket {
    pub fn wakeup() -> DhcpPacket {
        DhcpPacket {
            operation: DhcpOp::BootRequest,

            htype: 0x01,
            hlen: 0x06,
            hops: 0x00,

            xid: 0x0000_0000,

            secs: 0x0000,
            flags: DhcpFlags::empty(),

            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,

            sname: String::new(),
            file: String::new(),

            chaddr: MacAddress::NULL,
            options: DhcpOptions::from(vec![DhcpOption::MessageType(DhcpMessageType::Discover)]),
        }
    }

    pub fn discover(client_mac: MacAddress, req_addr: Option<Ipv4Addr>) -> Self {
        let mut options: DhcpOptions = vec![DhcpOption::ParameterRequestList(vec![
            OPT_CODE_SUBNET_MASK,
            OPT_CODE_ROUTER,
            OPT_CODE_DOMAIN_NAME,
            OPT_CODE_DOMAIN_NAME_SEVER,
        ])]
        .into();

        if let Some(addr) = req_addr {
            options.push(DhcpOption::RequestedIpAddr(addr))
        }

        DhcpPacket {
            operation: DhcpOp::BootRequest,
            htype: 0x01,
            hlen: 0x06,
            hops: 0x00,
            xid: random::<u32>(),
            secs: 0x0000,
            flags: DhcpFlags::empty(),
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: client_mac,
            sname: String::new(),
            file: String::new(),
            options,
        }
    }

    pub fn offer(
        discover: &DhcpPacket,
        server_ip: Ipv4Addr,
        assigned_ip: Ipv4Addr,
        mut ops_response: Vec<DhcpOption>,
    ) -> DhcpPacket {
        ops_response.insert(0, DhcpOption::MessageType(DhcpMessageType::Offer));
        DhcpPacket {
            operation: DhcpOp::BootReply,
            htype: 0x01,
            hlen: 0x06,
            hops: 0x00,
            xid: discover.xid,
            secs: 0x0000,
            flags: DhcpFlags::empty(),
            ciaddr: discover.ciaddr,
            yiaddr: assigned_ip,
            siaddr: server_ip,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: discover.chaddr,
            sname: String::new(),
            file: String::new(),
            options: DhcpOptions::from(ops_response),
        }
    }
}

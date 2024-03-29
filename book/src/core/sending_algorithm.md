# A conceptual sending algorithm

With the knowledge of previous chapters, lest discuss a conceptual sending algorithm,
starting from the async API ending at send packets.

## IP Version 4 

TODO

## IP Version 6

> Szenario:
> Sending a TCP Data packet on an allready open TCP connection

1) The user calls into the async API using e.g. `AsyncWrite::write` on a `TcpStream`
   - This call will be forwarded to the IO plugin (if one exists), and the relevant TCP component
   - The TCP component will add the new data to its buffers and then emit the underlying
     IP packet needed to facilitate the TCP connection
2) The TCP component emits an `IPv6Packet` to the IP stack
   - let's assume that the IP source address is `::` but the IP destination address is a known unicast address
   - let's also assume that the socket is not pinned to a specific interface, but rather able to use all interfaces
     of the host
3) The IP stack will first check the destination address: If the destination address is `::` the sending will fail
4) **If** the IP source address is unspecified, a source address will be selected according to the source
   address selection mechanisms defined by RFC 6724.
   - This process depends on three variables: The available addresses, the policies table and the given destination address
   - For some rare cases, the IP stack also allows `::` as a valid source address, e.g. for NDP Neighbor solicitations
5) **If** the packet is address to the node itself, so its addressed to self, the IP stack will emit the packet onto the input
   gate of the relevant interface for ethernet devices, or just send it using a loopback device.
6) **If** no interface binding was specified, the IP stack will determine the sending interface based on the choosen source
   address.
   - Sending packets with IP source address `::` thus allways requires a specified interface binding.
7) Next the IP stack will determine the next hop required to reach the destintation address.
   - On hosts this only check whether the destination is on-link or off-link. Off link destintations are forwarded to
     a router from the default router list.
   - On routers, this table contains the fowarding rules, derived from the routing rules of associated routing deamons.
   - Not that next-hop determination results are cached in the destination cache, so lookups into the raw tables are avoided
     whenever possible
8) After the next hop is determined, the link-layer address resolution will start. The IP stack will lookup the MAC address of
   the next hop. **If** no address is known, the node will send neighbor solicitations using NDP and queue the packet for later delivery.
   - Should this fail, the packets will be dropped and an error will be emitted if higher level components are able to handle the error
9) With the determined link layer destination the IP packet is encapuslated into a ethernet datagram (via `Message`) and forwarded to
   the sending interface. The interface will emit the datagram onto the underlying connections as soon as possible
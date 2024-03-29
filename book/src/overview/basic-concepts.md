# Basic concepts

As the previous chapter explained, an IO plugin without further configuration does almost nothing.
This is intended. A network node without any network connection or any semblance of connectivity
is useless. Additionally INET does not automatically use any gates of a module, without explicitly
being told so. This enables user to restrict INET generated traffic to a select few gates.

This chapter will discuss the basic concepts and configuration options from the perspective of a
simple host.

> All references in this chapter refer to the API of the core crate `inet`. So interpret `a::b` as `inet::a::b`.

## Interfaces

Any INET traffic is received and send by an `Interface`. An interface represents the logical binding
between an `NetworkDevice`, capable of receiving or sending messages, and some assigned addresses.
Network devices can either use a set of gates to receive and send messages, or just use `schedule_in`
to send messages to itself, implementing a loopback interface. Addresses can be assigned to interfaces
to act as both source addresses for outgoing packets, as well as target addresses incoming addresses.
As soon as an address is assigned, INET will process packets address to the binding.

Interfaces can be created in various ways, but the most basic case uses `interfaces::add_interface`. 
Various constructors allow for the creation if interfaces with preassigned address either for IPv4
or IPv6. If user are ok with IPv6 only interfaces, `interfaces::Interface::empty` is the easiest
solution, without a need to assign an address (IPv6 autoconfigures link local addresses + stateless autocfg).

The only component allways required to create an interface is a network device. These devices should almost
allways be created using the same gate as both input and output (use `interfaces::NetworkDevice::gate`). Providing
different gates is technically supported, but partically very hard to handle if both gates do not exactly behave
equivalent to a single-gate solution. Additionally a network device expects the attached gate chain to contain
at least one channel (must not be on the first chain link, but somewhere). Non-delayed devices are also 
allowed but emit warnings, since instantaneous networking is not expected by the current standards.

> A network device will only send onto non-busy channels, independently of any channel buffers. If a burst of packets 
> needs to be send the IO plugin will rather buffer them internally. Also sending manual messages to a gate-chain
> administed by INET may lead to unexpected side effects in the IO plugin.

## Ethernet

INET simulates ethernet traffic. This means that every message send by INET is either:
- a self scheduled message, either a `KIND_LINK_UPDATE` or a `KIND_IO_TIMEOUT`
- or a networking packet representing an ethernet datagram
  
The ethernet header is encoded directly into the `Message` struct itself, using the 
`src` and `dest` fields respectivly. The `MessageKind` is used as the ETHERTYP field. 
Other link layer effects such as packet collision or bit errors
are not supported, and likely never will be. The content of the message is any ethernet encapsualed
payload INET can send. Currently that includes:

- An `Ipv4Packet`
- An `ArpPacket`
- An `Ipv6Packet`

Note that all these packets are stored as is, rather then being serialized into bytevectors.
For now this is done, to improve performance and increase debuggabilty. Anything within a
IP packet is however serialized.

## Async Socket API

The primary "product" of the core crate are the async socket implementations, mirroring `tokio::net`.
These sockets can be used just like their tokio counterparts, assuming an interface is adequatly configured
The IO plugin will then consume any UDP or TCP packets and reroute their contents into the async API,
finally being forwarded to the user as the result of read/write calls to the socket object. Both
the UDP and TCP implementation are RFC compliant and fully featured, however without OS specific 
optimizations. 

```rust
use inet::TcpStream;
// in `at_sim_start`
tokio::spawn(async move {
    let sock = TcpStream::connect("192.168.0.103:8000").await?;
    sock.write(b"Hello world").await?;

    let mut buf = [0; 128];
    sock.read(&mut buf).await?;
    assert_eq!(String::from_utf8_lossy(&buf), "Hello back");
});
```

## Configuration functions

Almost all components of the networking stack have associated configurations, that
can be changed using the appropiate function in the API. The implications of changing 
a config mid-flight is discussed seperatedly for each component.

## Debugging 

INET fully supports `tracing` and with a scope aware logger, provided by `des::tracing`, also scope
aware traces of internal computations. As a general rule, INET does not emit INFO level events, only 
DEBUG and TRACE level events. Should an error occure internally INET may also emit WARN and ERROR level
events, but this only includes major failures, that may be of interest to the user, not minor failures
like a failed address resolution.

Should tracing not suffice, INET also enables packet captures with the feature flag `libpcap` and the 
`inet-pcap` crate. See [TODO] for more infomation.
# Overview

INET is a framework build onto of the `des` simulation framework. INET provides a
networking implementations roughly based on the linux network stack. This includes 
networking interface specifcation, including all relevant link layer protocol implementations,
as well as full socket implementations, mirroring `tokio::net`.

## Crates

As a networking implementations is rather large, INET is seperated into multiple crates:

- `inet`: This is the core crate that provides a minmal version of all basic functions of a networking stack,
          including a UDP and TCP implementations and all types mirroring `tokio::net`
- `inet-types`: This crate is a depedency of `inet` implementing packet parsing and pure datatypes, often used
                by upstream crates.
- `inet-bpg`: This crates implements the Border Gateway Protocol (BGP) and provides routing deamons to integrate
              BGP rules into the inet core module.
- `inet-rip`: Similarly, this crates implements the Routing Information Protocol (RIP) and provides routing deamons to integrate
              RIP rules into the inet core module.
- `inet-dns`: The core crate `inet`, does implement name lookups using the `lookup_host` function, but by default, these lookups
              do not result in DNS queries into the simulated network. This crate add both a local DNS resolver that does send queries
              as well as a DNS Nameserver implementation, to respond to these queries.
- `inet-pcap`: Debugging network applications can be rather complicated. To make debugging easier this crate provides tools to
               capture packets in the simulated network and export them as `.pcap` files (`.pcapng` is also supported).

## Requirements

Since INET is a networking framework, it obviously requires the feature `des/net`. Additionally INET also requires
the feature `des/async`, since a significant part of the API in the core crate such as `TcpStream` are async, just
like their `tokio` counterparts.

Additionally INET also requires the `--tokio-unstable` compile flag, inherited from `des`, to remove randomness
from the underlying tokio runtime, thus archiving a fully deterministic network simulation. To add this compile flag add
a `.cargo/config.toml` to your workspace:

```
[build]
rustflags = ["--cfg", "tokio_unstable"]
```

## Notice

INET is still very early in development (< 0.2.0), so expect things to break.
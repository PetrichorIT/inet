ToDo
===

- implement resolver as a extension DnsResolver { Option<Sender> }
- resolve() checks where there is a sender, if not then spawn a tokio::task with the resolver and the (rx, tx) pair
- use extension as hook

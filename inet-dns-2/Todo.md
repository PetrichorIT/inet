ToDo
===

- RR timeouts for cached entries
- RR timeouts for slave nodes
- better request multiplexing / timeout management per query
- iterative resolver: allow auth+cache combined queries


- Store SourceQuery as Arc<SQ> in  active_transactions, nameserver_quey, etc
- SQ contains question, client, connection type, options like rd ra, tx-num (client side)

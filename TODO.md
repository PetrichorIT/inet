# TCP

TcpListener::accept acts as a initilization point for stream establishment.
Only once accept has been called can a new stream be created, thus a handshake 
be made. This has the sideeffect that one active handshake (aka one call of accept)
blocks all other handshakes. Decouple socket creation / stream creation from accept
and make accept be just a queue of allready handshaked streams,.
Implement accept using a mpsc::channel (with listener_backlog) as limit
try_send and async recv. 

Questions: When queue full, deny entry at handshake initiaion or allow handshakes to be made
and the reset? How to deal with in-progress handshakes
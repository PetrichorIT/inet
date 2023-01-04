# Proposal '1: Optimize TCP Window updates

As of ed09216f576b255c43923a0cdc6c56f86c57e19e
window updates were only send if a full buffer was cleared,
or passivly if data was acked. This was inefficenit because
allready free memory was not advertised. Thus now all
non-zero read operations result in a window updates.

Problem:
Should multiple read operations occurr within one event
such as reading 1500 byte in 3 slice of 500 byte three
window updates will be send although the last one
hold all nesecarry information.

Proposed soloution:
Instead of sending the updates as part of the read call
call a defered function (using Plugin::defer) to determine
at the end of an event if a window updates is nessecary.
If yes send it then.

Pros:

-   Only requrired window updates
-   Easy implemention
-   Window update logic isolated

Cons:

-   Needs new IOContext api
-   window updates are allways scheduled last, behind send data packets

Notes:
The fact that window updates are last is not as bad since
A) the calls were (WR) so that would happen either way
B) the calls were (RW) so the data packets allready advertise the window

Improvments:
Detect case B to safe on the window update, since it is allready carried by the data packet.

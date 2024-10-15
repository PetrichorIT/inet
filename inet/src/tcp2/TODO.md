# MSS computation

"""
If an MSS Option is not received at connection setup, TCP implementations MUST assume a
default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15).
"""

We do set default MSS as config default values and always end MSS, but maybe another peer does not. What if
we do NOT recv a MSS but have a non-default one.
-> we send MSS -> peer will recognize and take min
-> peer may not send updated MSS (is not required) so we will never now about the peers default
-> we may have a higher MSS than the peer (lower would be synced since peer takes MIN)

# Path MTU discovery

# Close TIMEWAIT after LINGER

# OPTIONS: SO_LINGER

# Wrong WINDOW cmp

Most comparispns of is_between_wrapped or wrapping_lt uses the wend
computed as NXT + WND. WND is however not the window with cong control.
Fix by updating WND accordingly instead of recv_window() get

# Off by 1 erros with is_between_wrapped()

The original impl uses wrapping_sub to handle the x = start case.
I do it manually. Check if wrapping_sub(1) is still needed

# ICMP demultiplexing on IP layer

ICMP messages V4 are assigned to sockets, based on the src addr. This is not
a good idea, since e.g. multiple connections may be established to the same peer,
differnt ports and one of these connections might rcv a port-unreachable while
others do not.

# ICMP V6 DEMUX

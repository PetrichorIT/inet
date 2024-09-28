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

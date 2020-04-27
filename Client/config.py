
########################################################################
#
# Address configuration for MulticastSenderReceiverConfig.py
#
########################################################################

# Two sample multicast addresses to experiment with.

MULTICAST_ADDRESS = "239.0.0.10"
# MULTICAST_ADDRESS = "239.0.0.11"

# The UDP port to which we will be sending/receiving.

MULTICAST_PORT = 2000

# The multicast address and interface (address) are part of the add
# membership request that is passed to the lower layers. If you choose
# "0.0.0.0", the system will select the interface, which will probably
# work ok in most cases. In more complex situations, where, for
# example, you may have multiple network interfaces, you may have to
# specify the interface explicitly, by using its address.

RX_IFACE_ADDRESS = "0.0.0.0"
# RX_IFACE_ADDRESS = "192.168.1.22"

# The receiver socket bind address. This is used at the IP/UDP level
# to filter incoming multicast receptions. Using "0.0.0.0" should work
# ok but if for example, the same host is receiving multiple mutilcast
# groups on the same port, each application may receive all multicast
# group transmissions.

# RX_BIND_ADDRESS = MULTICAST_ADDRESS
RX_BIND_ADDRESS = "0.0.0.0"

########################################################################
# Define some things used in MulticastSenderReceiverConfig.py

# Sender:
MULTICAST_ADDRESS_PORT = (MULTICAST_ADDRESS, MULTICAST_PORT)

# Receiver:
BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, MULTICAST_PORT)

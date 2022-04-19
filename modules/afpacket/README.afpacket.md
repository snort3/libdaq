AFPacket Module
===============

A DAQ module built on top of the Linux memory-mapped packet socket interface
(AF_PACKET).  This interface provides direct access to copies of raw packets
received on Linux network devices in an adjuct ring buffer.  It supports both
passive and inline modes.

If you want to run AFPacket in inline mode, you must craft the device string as
one or more interface pairs, where each member of a pair is separated by a
single colon and each pair is separated by a double colon like this:

    eth0:eth1

or this:

    eth0:eth1::eth2:eth3

An exception to this rule is when this DAQ is used in GWLB environment
(see below) where a single interface is used for ingress and egress.

Passive mode can listen on multiple interfaces simultaneously with a similarly
crafted input specification consisting of colon-separated interface names like
this:

    eth0:eth1:eth2:eth3

The AFPacket DAQ module will always run the interfaces in promiscuous mode.

Use in GWLB environment
-----------------------
A Gateway Load Balancer (GWLB) is used to deploy, scale and manage third-party
virtual appliances in a public cloud environment. It provides a bump in the
wire technology and ensures that traffic to a public endpoint is first
processed by the virtual appliance before being sent to the target application. The
GWLB and registered virtual appliances exchange application traffic by using
some encapsulation protocol like Geneve (RFC 8926) or VxLAN (RFC 7348).

This DAQ could be used in such an environment by using daq_gwlb as wrapper
on this daq. To use AFPacket in this mode, a single interface is to be
specified in the device string and the inline mode of operation enabled.

Also see README.gwlb.md

Requirements
------------
* Linux kernel version 3.14 or higher
* libpcap is optional (required for BPF support)

Interface Preparation
---------------------
Before trying to use any interfaces with AFPacket, they must first be brought
UP via something like ifconfig (ifconfig eth0 up) or ip (ip link set eth0 up).

Additionally, it is a good idea disable receive-side offloading that results
in frames larger than the configured snaplen.  Not doing so will result in the
application seeing truncated packet data.  This is especially bad when operating
in inline mode as it will then forward only the truncated portion of the packet
that is available to it.  To disable LRO (Large Receive Offload) and GRO
(Generic Receive Offload), use ethtool like this:

    ethtool -K eth0 lro off gro off

Ring Buffer Memory
------------------
By default, the afpacket DAQ allocates 128MB for packet memory divided evenly
across all participating interfaces.  You can change this with the
'buffer_size_mb' variable.

Note that the total allocated is actually higher, here's why.  Assuming the
default packet memory with a snaplen of 1518, the numbers break down like this:

* The frame size is 1518 (snaplen) + the size of the AFPacket header (66 bytes)
  = 1584 bytes.

* The number of frames is 128 MB / 1518 = 84733.

* The smallest block size that can fit at least one frame is  4 KB = 4096 bytes
  @ 2 frames per block.

* As a result, we need 84733 / 2 = 42366 blocks.

* Actual memory allocated is 42366 * 4 KB = 165.5 MB.

BPF Support
-----------
The AFPacket DAQ module will implement BPF filtering if the LibPCAP development
headers and libraries are available at build time.  This results in a library
dependency on libpcap at runtime for the AFPacket DAQ module.

TX Ring Support
---------------
AFPacket TX ring support is currently implemented but disabled by default due to
suboptimal performance results in testing.  There are plans to try to address
this in future releases.  If you want to forcibly enable using the TX ring, you
can override the default with the 'use_tx_ring' variable.

NOTE: When TX rings are in use, the RX buffer memory given to each interface is
halved to accomodate the TX ring buffer memory.

Fanout (Kernel Loadbalancing)
-----------------------------
More recent Linux kernel versions (3.1+) support various kernel-space
loadbalancing methods within AFPacket configured using the PACKET_FANOUT ioctl.
This allows you to have multiple AFPacket DAQ module instances processing
packets from the same interfaces in parallel for significantly improved
throughput.

To configure PACKET_FANOUT in the AFPacket DAQ module, two DAQ variables are
used:

    fanout_type=<hash|lb|cpu|rollover|rnd|qm>

and (optionally):

    fanout_flag=<rollover|defrag>

In general, you're going to want to use the 'hash' fanout type, but the others
have been included for completeness.  The 'defrag' fanout flag is probably a
good idea to correctly handle loadbalancing of flows containing fragmented
packets.

Please read the man page for 'packet' or packet_mmap.txt in the Linux kernel
source for more details on the different fanout types and modifier flags.


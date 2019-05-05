PCAP Module
===========

A DAQ module built around LibPCAP that supports both read-file and passive
interface modes.  All input specifications are directly passed to LibPCAP and
thus should match the input given to something like the -i or -r options of
tcpdump.

You can override the buffer size PCAP uses with the 'buffer_size' variable.

The PCAP DAQ module defaults to listening in promiscuous mode.  To listen in
non-promiscuous mode instead, use the 'no_promiscuous' variable.

The PCAP DAQ module defaults to using immediate ((less-buffered or unbuffered)
delivery mode.  This behavior can be disabled with the 'no_immediate' variable.
This immediate delivery mode can be particularly useful on modern Linux systems
with TPACKET_V3 support.  LibPCAP will attempt to use this mode when it is
available, but it introduces some potentially undesirable behavior in exchange
for better performance.  The most notable behavior change is that the packet
timeout will never occur if packets are not being received, causing the poll()
to potentially hang indefinitely.  Enabling immediate delivery mode will cause
LibPCAP to use TPACKET_V2 instead of TPACKET_V3.

The PCAP DAQ module does not count filtered packets.

Requirements
------------
* libpcap >= 1.5.0
    (LibPCAP 1.9.0 is available at the time of writing and is recommended.)

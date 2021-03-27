Savefile Module
===============

A DAQ module designed for performance-optimized readback of traditional pcap
savefiles.

The savefile DAQ module will map an entire pcap savefile into memory and then
directly access the contents to acquire DAQ message data.  Compared to the PCAP
DAQ module, this eliminates both the overhead of the libpcap API interface
itself as well as the copying of packet data into the DAQ message pool's data
buffers.

CAUTION: As mentioned above, the contents of the entire pcap savefile will be
mapped into memory and will not be released until the DAQ module is stopped.
Make sure not to load a file that is too large to fit in memory as that will
run the system out of memory once all of the packets in the file have been
accessed and everything has been paged into active memory.

Limitations
-----------

* Only pcap savefile format version 2.4 is supported.  This covers the past 22
years of savefiles produced by libpcap, so as long as you're not trying to read
pcapng or other newer formats, you're probably good.

* Only pcap savefiles with Ethernet data link types (DLT_EN10MB) are supported.

* The beginning of message data in messages received by the application can
easily be positioned at unaligned memory addresses.  This does not end well on
architectures that cannot handle unaligned memory accesses.

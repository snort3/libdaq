Dump Module
===========

A wrapper DAQ module that presents the configuration stack as inline-interface-
and injection-capable.  All packet messages that are finalized with a passing
verdict (PASS, REPLACE, WHITELIST, IGNORE) or injected will be written to a PCAP
savefile.  By default, the packet capture file will be named 'inline-out.pcap'
in the current directory.  The default filename can be overridden with the
'file' variable.  For historical reasons, the 'output' variable also exists and
accepts only one valid argument in 'none' to disable writing out a PCAP file
altogether.

The Dump DAQ module also supports capturing received packets to a separate PCAP
savefile.  This is disabled by default, but can be enabled with the 'dump-rx'
variable.  The 'dump-rx' variable takes an optional argument for the filename
to dump received packets to; it defaults to 'inline-in.pcap' if no argument is
given.

The output files can be automatically rolled (rotated) based on file size
and/or packet count.  The 'roll-size' variable takes a size in MiB and rolls
an output file when it reaches that size.  The 'roll-pkts' variable takes a
packet count and rolls an output file when it contains that many packets.  If
both are specified, an output file is rolled when either limit is reached.
When a file is rolled, the current file is closed and a new one is opened with
a numeric suffix appended to the configured filename, incrementing with each
roll.  For example, with the default TX output filename, the files would be
'inline-out.pcap', 'inline-out.pcap.1', 'inline-out.pcap.2', and so on.  The
TX and RX output files are tracked and rolled independently.

When running with multiple instances, the both the TX and RX output filenames
will be mangled to start with the instance ID followed by an underscore.  For
example, the default TX output filename would be '2_inline-out.pcap' for the
second instance.  Both the TX and RX output filenames must be bare (no directory
structure, relative nor absolute) in such a configuration.

Requirements
------------
* libpcap >= 1.0.0
    (LibPCAP 1.9.0 is available at the time of writing and is recommended.)

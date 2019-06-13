Dump Module
===========

A wrapper DAQ module that presents the configuration stack as inline-interface-
and injection-capable.  All packet messages that are finalized with a passing
verdict (PASS, REPLACE, WHITELIST, IGNORE) or injected will be written to a pcap
savefile.  By default, the packet capture file will be named 'inline-out.pcap'
in the current directory.  The default filename can be overridden with the
'file' variable.  For historical reasons, the 'output' variable also exists and
accepts only one valid argument in 'none' to disable writing out a pcap file
altogether.

Requirements
------------
* libpcap >= 1.0.0
    (LibPCAP 1.9.0 is available at the time of writing and is recommended.)

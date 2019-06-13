BPF Module
===========

A wrapper DAQ module that implements filtering on packet reception when given
a Berkeley Packet Filter (BPF) to operate with.  It adds the BPF capability to
the module stack that it is part of and will update the filtered count in the
DAQ statistics.  Filtered packet messages will be immediately finalized with a
PASS verdict.

This module uses BPF implementation from LibPCAP.

A nice, if incomplete, guide to BPF syntax can be found here:
<http://biot.com/capstats/bpf.html>

Requirements
------------
* libpcap >= 1.0.0
    (LibPCAP 1.9.0 is available at the time of writing and is recommended.)

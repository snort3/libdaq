**NOTE: This document is entirely out-of-date and potentially very inaccurate.**

NFQ Module
==========

NFQ is the new and improved way to process iptables packets:

    ./snort --daq nfq \
        [--daq-var device=<dev>] \
        [--daq-var proto=<proto>] \
        [--daq-var queue=<qid>]

    <dev> ::= ip | eth0, etc; default is IP injection
    <proto> ::= ip4 | ip6 |; default is ip4
    <qid> ::= 0..65535; default is 0

This module can not run unprivileged so ./snort -u -g will produce a warning
and won't change user or group.

Notes on iptables are given below.


Notes on iptables
=================

These notes are just a quick reminder that you need to set up iptables to use
the NFQ DAQs.  Doing so may cause problems with your network so tread
carefully.  The examples below are intentionally incomplete so please read the
related documentation first.

Here is a blog post by Marty for historical reference:

    http://archives.neohapsis.com/archives/snort/2000-11/0394.html

You can check this out for queue sizing tips:

    http://www.inliniac.net/blog/2008/01/23/improving-snort_inlines-nfq-performance.html

Use this to examine your iptables:

    sudo /sbin/iptables -L

Use something like this to set up NFQ:

    sudo /sbin/iptables
        -I <table> [<protocol stuff>] [<state stuff>]
        -j NFQUEUE --queue-num 1

Use something like this to "disconnect" snort:

    sudo /sbin/iptables -D <table> <rule pos>

Be sure to start Snort prior to routing packets through NFQ with iptables.
Such packets will be dropped until Snort is started.

The queue-num is the number you must give Snort.

These DAQs should be run with a snaplen of 65535 since the kernel defrags the
packets before queuing.  Also, no need to configure frag3.

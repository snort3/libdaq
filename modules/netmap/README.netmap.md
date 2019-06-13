Netmap Module
=============

A DAQ module built on top of the netmap project.  The netmap project is a
framework for very high speed packet I/O.  It is available on both FreeBSD and
Linux with varying amounts of preparatory setup required.  Specific notes for
each are given in following sections.

If you want to run netmap in inline mode, you must craft the device string as
one or more interface pairs, where each member of a pair is separated by a
single colon and each pair is separated by a double colon like this:

    em1:em2

or this:

    em1:em2::em3:em4

Inline operation performs Layer 2 forwarding with no MAC filtering, akin to the
AFPacket module's behavior.  All packets received on one interface in an inline
pair will be forwarded out the other interface unless dropped by the reader and
vice versa.

For passive operation, simply give a colon-separated list of interfaces to
listen on.  It will end up look the same as the inline specification except
without the double colon delimited pair concept.

IMPORTANT: The interfaces will need to be up and in promiscuous mode in order to
function ('ifconfig em1 up promisc').  The DAQ module does not currently do
either of these configuration steps for itself.

FreeBSD
-------
In FreeBSD 11.0, netmap has been integrated into the core OS and compiled into
the kernel by default.  You no longer need to recompile your kernel to add
netmap support.

Linux
-----
**NOTE: This section is entirely out-of-date and potentially very inaccurate.**

You will need to download the netmap source code from the project's repository:

    https://code.google.com/p/netmap/

Follow the instructions on the project's homepage for compiling and installing
the code:

    http://info.iet.unipi.it/~luigi/netmap/

It will involve a standalone kernel module (netmap_lin) as well as patching and
rebuilding the kernel module used to drive your network adapters. The following
drivers are supported under Linux at the time of writing (June 2014):

    e1000
    e1000e
    forcedeth
    igb
    ixgbe
    r8169
    virtio

TODO
----
- Support for attaching to only a single ring (queue) on a network adapter.
- Support for VALE and netmap pipes.

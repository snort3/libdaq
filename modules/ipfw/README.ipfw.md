IPFW Module
===========

A DAQ module for listening on BSD divert sockets.  The input specification given
to the DAQ module should be the integer value of the divert port number to
receive and process packets on.  The module is intrinsically operating in an
inline mode as any packets that it does not return to the kernel will be
dropped.

Packets will come up to the application with a datalink type of "RAW", which
means the packet data begins with the IP header.

Note: If nothing is listening on the specified divert socket port, the traffic
that was supposed to be diverted to it will be dropped.

Example Setup (FreeBSD)
-----------------------

The following steps set up a FreeBSD system with two data interfaces (em0 and
em1) and configure them as two routing interfaces with IPv4 addresses.  All
traffic that is received on either interface is sent to the divert socket on
port 8000 and forwarded when it is received back from the userspace
application.

1. Enable the firewall and configure it with the "open" template.

        sysrc firewall_enable="YES"
        sysrc firewall_type="open"
        service ipfw restart

2. Give the interfaces IPv4 addresses.

        ifconfig em0 172.16.1.1/24
        ifconfig em1 172.16.2.1/24

3. Enable gateway (routing) functionality.

        sysrc gateway_enable="yes"
        service routing restart

4. Load the ipdivert kernel module if it's not compiled in (default).

        kldload ipdivert
        To make this permanent, add ipdivert_load="YES" to /boot/loader.conf.

5. Define an ipfw rule with an arbitrary (but low) rule ID (75) that diverts all
traffic received on em0 and em1 to an arbitrary divert socket port (8000).

        ipfw add 75 divert 8000 all from any to any in recv em0
        ipfw add 75 divert 8000 all from any to any in recv em1

Note: If you are operating in a slightly more complicated setup with NAT via a
natd divert, you will want to add the two rules before and after the natd divert
rule.  For example, if em0 is the public interface and em1 is the internal
interface, the snippet of the final rule set around the nat divert rule should
look something like this:

    ipfw add 45 divert 8000 all from any to any in recv em1
    ipfw add 50 divert natd ip4 from any to any via em0
    ipfw add 55 divert 8000 all from any to any in recv em0

This will send all traffic coming in on the internal interface pre-NAT and all
traffic coming in on the public interace post-NAT to the divert socket so that
all traffic is using private addresses.

OpenBSD
-------
**NOTE: This section is entirely out-of-date and potentially very inaccurate.**

OpenBSD supports divert sockets as of 4.7, so we use the ipfw DAQ.

Here is one way to set things up:

1.  Configure the system to forward packets:

    $ sysctl net.inet.ip.forwarding=1
    $ sysctl net.inet6.ip6.forwarding=1

    (You can also put that in /etc/sysctl.conf to enable on boot.)

2.  Set up interfaces

    $ dhclient vic1
    $ dhclient vic2

3.  Set up packet filter rules:

    $ echo "pass out on vic1 divert-packet port 9000 keep-state" > rules.txt
    $ echo "pass out on vic2 divert-packet port 9000 keep-state" >> rules.txt

    $ pfctl -v -f rules.txt

4.  Analyze packets diverted to port 9000:

    $ ./snort --daq ipfw --daq-var port=9000

* Note that on OpenBSD, divert sockets don't work with bridges!

Additional Resources
--------------------

* FreeBSD online manual for IFPW: <https://www.freebsd.org/doc/handbook/firewalls-ipfw.html>

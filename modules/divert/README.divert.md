Divert Module
=============

A DAQ module for listening on BSD divert sockets.  The input specification given
to the DAQ module should be the integer value of the divert port number to
receive and process packets on.  The module is intrinsically operating in an
inline mode as any packets that it does not return to the kernel will be
dropped.

Packets will come up to the application with a datalink type of "RAW", which
means the packet data begins with the IP header.

On FreeBSD, the IPFW firewall subsystem is used to send packets to divert
sockets.  On OpenBSD, the PF firewall subsystem is used to do so.  Note that
the PF firewall is also available on FreeBSD, but it does not support diverting
packets like the OpenBSD implementation does.

Note: If nothing is listening on the specified divert socket port, the traffic
that was supposed to be diverted to it will be dropped.

Example Setup (FreeBSD)
-----------------------

The following steps set up a FreeBSD system with two data interfaces (em1 and
em2) and configures them as two routing interfaces with IPv4 addresses.  All
traffic that is received on either interface is sent to the divert socket on
port 8000 and forwarded when it is received back from the userspace
application.

1. Enable the firewall and configure it with the "open" template.

        sysrc firewall_enable="YES"
        sysrc firewall_type="open"
        service ipfw restart

2. Give the interfaces IPv4 addresses.

        ifconfig em1 172.16.1.1/24
        ifconfig em2 172.16.2.1/24

3. Enable gateway (routing) functionality.

        sysrc gateway_enable="yes"
        service routing restart

4. Load the ipdivert kernel module if it's not compiled in (default).

        kldload ipdivert
        To make this permanent, add ipdivert_load="YES" to /boot/loader.conf.

5. Define an ipfw rule with an arbitrary (but low) rule ID (75) that diverts all
traffic received on em1 and em2 to an arbitrary divert socket port (8000).

        ipfw add 75 divert 8000 all from any to any in recv em1
        ipfw add 75 divert 8000 all from any to any in recv em2

Note: If you are operating in a slightly more complicated setup with NAT via a
natd divert, you will want to add the two rules before and after the natd divert
rule.  For example, if em1 is the public interface and em2 is the internal
interface, the snippet of the final rule set around the nat divert rule should
look something like this:

    ipfw add 45 divert 8000 all from any to any in recv em2
    ipfw add 50 divert natd ip4 from any to any via em1
    ipfw add 55 divert 8000 all from any to any in recv em1

This will send all traffic coming in on the internal interface pre-NAT and all
traffic coming in on the public interace post-NAT to the divert socket so that
all traffic is using private addresses.

Example Setup (OpenBSD)
-----------------------

The following steps set up a OpenBSD system with two data interfaces (em1 and
em2) and configures them as two routing interfaces with IPv4 addresses.  All
traffic that is leaving on either interface is sent to the divert socket on
port 8000 and forwarded when it is received back from the userspace
application.

1. Configure the system to forward IPv4 packets.

        sysctl net.inet.ip.forwarding=1

    (You can also put that in /etc/sysctl.conf to enable on boot.)

2. Give the interfaces IPv4 addresses.

        ifconfig em1 172.16.1.1/24
        ifconfig em2 172.16.2.1/24

3. Add packet filter rules to the configuration and load them.

        echo "pass out on em1 divert-packet port 8000" >> /etc/pf.conf
        echo "pass out on em2 divert-packet port 8000" >> /etc/pf.conf

        pfctl -vf /etc/pf.conf

Note: With this configuration it seems like one direction of the traffic comes
off the divert socket with bad IP checksums.  I'm really not familiar enough
with OpenBSD/PF to figure out why.  This seems to be related, but it sounds
like it should have fixed it:
<https://lteo.net/blog/2015/01/06/dissecting-openbsds-divert-4-part-1-introduction/>

Additional Resources
--------------------

* FreeBSD online handbook for IFPW: <https://www.freebsd.org/doc/handbook/firewalls-ipfw.html>
* OpenBSD online manual for PF configuration:  <https://man.openbsd.org/pf.conf.5>

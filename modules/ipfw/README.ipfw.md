**NOTE: This document is entirely out-of-date and potentially very inaccurate.**

IPFW Module
===========

IPFW is available for BSD systems.  It replaces the inline version available in
pre-2.9 versions built with this:

    ./configure --enable-ipfw

This command line argument is no longer supported:

    ./snort -J <port#>

Instead, start Snort like this:

    ./snort --daq ipfw [--daq-var port=<port>]

    <port> ::= 1..65535; default is 8000

* IPFW only supports ip4 traffic.

FreeBSD
-------
Check the online manual at:

    http://www.freebsd.org/doc/handbook/firewalls-ipfw.html.

Here is a brief example to divert icmp packets to Snort at port 8000:

To enable support for divert sockets, place the following lines in the
kernel configuration file:

    options IPFIREWALL
    options IPDIVERT

(The file in this case was: /usr/src/sys/i386/conf/GENERIC; which is platform
dependent.)

You may need to also set these to use the loadable kernel modules:

/etc/rc.conf:
firewall_enable="YES"

/boot/loader.conf:
ipfw_load="YES"
ipdivert_load="YES"

$ dmesg | grep ipfw
ipfw2 (+ipv6) initialized, divert loadable, nat loadable, rule-based
forwarding disabled, default to deny, logging disabled

$ kldload -v ipdivert
Loaded ipdivert, id=4

$ ipfw add 75 divert 8000 icmp from any to any
00075 divert 8000 icmp from any to any

$ ipfw list
...
00075 divert 8000 icmp from any to any
00080 allow icmp from any to any
...

* Note that on FreeBSD, divert sockets don't work with bridges!

Please refer to the following articles for more information:

https://forums.snort.org/forums/support/topics/snort-inline-on-freebsd-ipfw
http://freebsd.rogness.net/snort_inline/

NAT gateway can be used with divert sockets if the network environment is
conducive to using NAT.

The steps to set up NAT with ipfw are as follows:

1. Set up NAT with two interface em0 and em1 by adding
the following to /etc/rc.conf

gateway_enable="YES"
natd_program="/sbin/natd"   # path to natd
natd_enable="YES"           # Enable natd (if firewall_enable == YES)
natd_interface="em0"       # Public interface or IP Address
natd_flags="-dynamic"       # Additional flags
defaultrouter=""
ifconfig_em0="DHCP"
ifconfig_em1="inet 192.168.1.2 netmask 255.255.255.0"
firewall_enable="YES"
firewall_script="/etc/rc.firewall"
firewall_type="simple"

Here em0 is connected to external network and em1 to host-only LAN.

2. Add the following divert rules to divert packets to Snort above and
below the NAT rule in the "Simple" section of /etc/rc.firewall.

   ...
   # Inspect outbound packets (those arriving on "inside" interface)
   # before NAT translation.
   ${fwcmd} add divert 8000 all from any to any in via ${iif}
   case ${natd_enable} in
   [Yy][Ee][Ss])
       if [ -n "${natd_interface}" ]; then
           ${fwcmd} add divert natd all from any to any via
${natd_interface}
       fi
       ;;
   esac
   ...
   # Inspect inbound packets (those arriving on "outside" interface)
   # after NAT translation that aren't blocked for other reasons,
   # after the TCP "established" rule.
   ${fwcmd} add divert 8000 all from any to any in via ${oif}

OpenBSD
-------
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


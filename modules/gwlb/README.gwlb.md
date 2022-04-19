DAQ GWLB
--------

Wrapper DAQ module to use for GWLB use case.

A Gateway Load Balancer (GWLB) is used to deploy, scale and manage third-party
virtual appliances in a public cloud environment. It provides a bump in the
wire technology and ensures that traffic to a public endpoint is first
processed by the virtual appliance before being sent to the target application. The
GWLB and registered virtual appliances exchange application traffic by using
some encapsulation protocol like Geneve (RFC 8926) or VxLAN (RFC 7348).

This DAQ module, used as a wrapper over DAQ afpacket, is for deploying snort3
as a virtual appliance.

At the virtual appliance, packets ingress and egress at the same interface.
Incoming packets are handed off to snort as is. Outgoing packets have their
outer L2 and L3 addresses swapped when needed.  Packets injected by snort may
or may not require this address translation, depending upon the direction of
the packet.

The minimal arguments to use this DAQ module are
    snort --daq afpacket --daq gwlb -i <intf> --snap <snap len> -Q

Providing the snap length is optional but highly recommended since the
encapsulated packet may exceed ethernet MTU.

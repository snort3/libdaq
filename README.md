LibDAQ: The Data AcQuisition Library
====================================

Overview
--------

LibDAQ is a pluggable abstraction layer for interacting with a data source
(traditionally a network interface or network data plane).  Applications using
LibDAQ use the library API defined in daq.h to load, configure, and interact
with pluggable DAQ modules.

DAQ Modules
-----------

Each DAQ module implements some or all parts of the DAQ module API depending on
its type and capabilities.  There are two main classes of DAQ modules: base
modules and wrapper modules.  Base modules provide a full-fledged and
independently usable implementation of the DAQ module API, while wrapper modules
provide a subset of the API that is applied in a decorator pattern when combined
with a base module.

DAQ Instances
-------------

A DAQ instance is an instantiation of a DAQ configuration that contains exactly
one base module and zero or more wrapper modules.  The wrapper modules are
layered on top of the base module in LIFO order (sometimes referred to as a
"module stack") and the overrides present in the wrapper module API
implementations will be resolved from the top down.  The basic life cycle of a
DAQ instance once a configuration is defined is as such: instantiation,
starting, stopping, and destruction (instantiate => start => stop => destroy).

DAQ Messages
------------

At its core, LibDAQ is about receiving and processing data.  The fundamental
unit used for passing data from a DAQ instance up to the application is the DAQ
message.  Each message is composed of three main components: a type, a header,
and some data.  For example, the message used to convey a packet is of the DAQ
Packet Message type with an associated DAQ Packet Header and the actual packet
data itself.  Messages are received in vectors/batches from the DAQ instance and
finalized individually.  The vector of messages received is free to be
heterogeneous based entirely on what the DAQ instance happens to yield.

The basic main loop for any simple LibDAQ program will look something like this:
```
DAQ_Msg_h msgs[16];
DAQ_RecvStatus rstat;
unsigned num_recv = daq_instance_msg_receive(instance, 16, msgs, &rstat);
<Check the receive status in rstat for error conditions and bail>
for (unsigned idx = 0; idx < num_recv; idx++)
{
    DAQ_Msg_h msg = ctxt->msgs[idx];
    <Perform work on the DAQ message that results in a verdict>
    daq_instance_msg_finalize(instance, msg, DAQ_VERDICT_*);
}
```
Repeated inside of a loop until an error or otherwise terminal condition is met.

DAQ messages may be finalized in any order and even finalized many receive calls
later.  Once a message is finalized, the message handle should be considered
invalid by the application, as well as any and all of its data.

This is a large departure from the way LibDAQ 2.x worked.  Previously, packets
were received via a callback from a looping acquisition function and a verdict
for each packet was the required return value from the callback.  Once the
callback returned, any ownership or control of the packet was surrendered back
to the DAQ instance.  The new paradigm allows for far more control by the
application, with the responsibility that comes along with that power.

DAQ IOCTLs
----------

DAQ IOCTLs (input/output controls) represent a semi-generic method for
communicating with special functionality in the DAQ modules and the data planes
they are abstracting.  There are a set of first-class IOCTLs defined in the API,
while IOCTL command IDs between 1025 and 65535 can be used for custom IOCTLs.
Each IOCTL takes a pointer to an argument and a length and beyond that is
generally free-form.  An example of a first-class DAQ IOCTL would be the
CREATE_EXPECTED_FLOW command, which will request that the backing data source
set up the expectation for a new flow based on a potentially complex set of
features to identify the expected flow with.

Although the majority of them currently do, there is no requirement that IOCTL
operations pertain to a particular DAQ message or flow.

For those familiar with LibDAQ 2.x, the IOCTL functionality has subsumed the
previously separate Modify Flow, Query Flow, Data Plane Add Data Channel, and
Get Device Index functions.

Build and Install
-----------------

LibDAQ is a standard autotools project and builds and installs as such:

    ./configure
    make
    make install

If building from git, you will need to do the following to generate the
configure script prior to running the steps above:

    ./bootstrap

This will build and install both the library and modules.

When the DAQ library is built, both static and dynamic flavors will be
generated.  The various DAQ modules will be built if the requisite headers and
libraries are available.  You can disable individual modules, etc. with options
to configure.  For the complete list of configure options, run:

    ./configure --help


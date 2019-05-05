LibDAQ: The Data AcQuisition Library
====================================

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


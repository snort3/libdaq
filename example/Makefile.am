
AM_CFLAGS = -Wall -I$(top_srcdir)/api -I$(top_srcdir)/sfbpf

bin_PROGRAMS = daqtest daqtest-static

daqtest_SOURCES = daqtest.c
daqtest_LDADD = ${top_builddir}/api/libdaq.la

daqtest_static_CFLAGS = $(AM_CFLAGS) -DUSE_STATIC_MODULES
daqtest_static_SOURCES = daqtest.c
daqtest_static_LDFLAGS = -static-libtool-libs
daqtest_static_LDADD = ${top_builddir}/api/libdaq.la ${top_builddir}/modules/libdaq_static_modules.la $(STATIC_LIBS)

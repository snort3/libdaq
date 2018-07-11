
AM_CFLAGS = -Wall -I$(top_srcdir)/api

bin_PROGRAMS = daqtest daqtest-static

daqtest_SOURCES = daqtest.c
daqtest_LDADD = ${top_builddir}/api/libdaq.la -lpthread

daqtest_static_CFLAGS = $(AM_CFLAGS) -DUSE_STATIC_MODULES
daqtest_static_SOURCES = daqtest.c
daqtest_static_LDFLAGS = -static-libtool-libs $(PCAP_LDFLAGS)
daqtest_static_LDADD = ${top_builddir}/api/libdaq.la ${top_builddir}/modules/libdaq_static_modules.la $(STATIC_LIBS) -lpthread

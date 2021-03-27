
AM_CFLAGS = -Wall -I$(top_srcdir)/api

bin_PROGRAMS = daqtest daqtest-static

# Dynamic modules build
daqtest_SOURCES = daqtest.c decode.h netinet_compat.h
daqtest_LDADD = ${top_builddir}/api/libdaq.la -lpthread

# Static modules build
daqtest_static_CFLAGS = $(AM_CFLAGS) -DUSE_STATIC_MODULES
daqtest_static_SOURCES = daqtest.c decode.h netinet_compat.h
daqtest_static_LDFLAGS = -static-libtool-libs $(PCAP_LDFLAGS)
daqtest_static_LDADD = ${top_builddir}/api/libdaq.la -lpthread
if BUILD_AFPACKET_MODULE
daqtest_static_CFLAGS += -DBUILD_AFPACKET_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/afpacket/libdaq_static_afpacket.la $(DAQ_AFPACKET_LIBS)
endif
if BUILD_BPF_MODULE
daqtest_static_CFLAGS += -DBUILD_BPF_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/bpf/libdaq_static_bpf.la $(DAQ_BPF_LIBS)
endif
if BUILD_DIVERT_MODULE
daqtest_static_CFLAGS += -DBUILD_DIVERT_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/divert/libdaq_static_divert.la
endif
if BUILD_DUMP_MODULE
daqtest_static_CFLAGS += -DBUILD_DUMP_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/dump/libdaq_static_dump.la $(DAQ_DUMP_LIBS)
endif
if BUILD_FST_MODULE
daqtest_static_CFLAGS += -DBUILD_FST_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/fst/libdaq_static_fst.la $(DAQ_FST_LIBS)
endif
if BUILD_NETMAP_MODULE
daqtest_static_CFLAGS += -DBUILD_NETMAP_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/netmap/libdaq_static_netmap.la
endif
if BUILD_NFQ_MODULE
daqtest_static_CFLAGS += -DBUILD_NFQ_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/nfq/libdaq_static_nfq.la $(DAQ_NFQ_LIBS)
endif
if BUILD_PCAP_MODULE
daqtest_static_CFLAGS += -DBUILD_PCAP_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/pcap/libdaq_static_pcap.la $(DAQ_PCAP_LIBS)
endif
if BUILD_SAVEFILE_MODULE
daqtest_static_CFLAGS += -DBUILD_SAVEFILE_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/savefile/libdaq_static_savefile.la
endif
if BUILD_TRACE_MODULE
daqtest_static_CFLAGS += -DBUILD_TRACE_MODULE
daqtest_static_LDADD += ${top_builddir}/modules/trace/libdaq_static_trace.la
endif

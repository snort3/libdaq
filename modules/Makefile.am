bin_SCRIPTS = daq-modules-config

pkglib_LTLIBRARIES =

lib_LTLIBRARIES = libdaq_static_modules.la
libdaq_static_modules_la_SOURCES = \
daq_static_modules.c \
daq_static_modules.h
libdaq_static_modules_la_CPPFLAGS = $(AM_CPPFLAGS)
libdaq_static_modules_la_LDFLAGS = -static -avoid-version

if BUILD_AFPACKET_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_afpacket.la
    daq_afpacket_la_SOURCES = daq_afpacket.c
    daq_afpacket_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_afpacket_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
if LIBPCAP_AVAILABLE
    daq_afpacket_la_CPPFLAGS += $(PCAP_CPPFLAGS)
    daq_afpacket_la_LDFLAGS += $(PCAP_LDFLAGS)
    daq_afpacket_la_LIBADD = -lpcap
endif
endif
    libdaq_static_modules_la_SOURCES += daq_afpacket.c
    libdaq_static_modules_la_CPPFLAGS += -DBUILD_AFPACKET_MODULE
if LIBPCAP_AVAILABLE
    libdaq_static_modules_la_CPPFLAGS += $(PCAP_CPPFLAGS)
endif
endif

if BUILD_BPF_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_bpf.la
    daq_bpf_la_SOURCES = daq_bpf.c
    daq_bpf_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    daq_bpf_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    daq_bpf_la_LIBADD = -lpcap
endif
    libdaq_static_modules_la_SOURCES += daq_bpf.c
    libdaq_static_modules_la_CPPFLAGS += -DBUILD_BPF_MODULE $(PCAP_CPPFLAGS)
endif

if BUILD_PCAP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_pcap.la
    daq_pcap_la_SOURCES = daq_pcap.c
    daq_pcap_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    daq_pcap_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    daq_pcap_la_LIBADD = -lpcap
endif
    libdaq_static_modules_la_SOURCES += daq_pcap.c
    libdaq_static_modules_la_CPPFLAGS += -DBUILD_PCAP_MODULE $(PCAP_CPPFLAGS)
endif

if BUILD_DUMP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_dump.la
    daq_dump_la_SOURCES = daq_dump.c
    daq_dump_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    daq_dump_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    daq_dump_la_LIBADD = -lpcap
endif
    libdaq_static_modules_la_SOURCES += daq_dump.c
    libdaq_static_modules_la_CPPFLAGS += -DBUILD_DUMP_MODULE $(PCAP_CPPFLAGS)
endif

if BUILD_IPFW_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_ipfw.la
    daq_ipfw_la_SOURCES = daq_ipfw.c
    daq_ipfw_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_ipfw_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    libdaq_static_modules_la_SOURCES += daq_ipfw.c
    libdaq_static_modules_la_CPPFLAGS += -DBUILD_IPFW_MODULE
endif

if BUILD_NFQ_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_nfq.la
    daq_nfq_la_SOURCES = daq_nfq.c
    daq_nfq_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_nfq_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
    daq_nfq_la_LIBADD = -lmnl
endif
    libdaq_static_modules_la_SOURCES += daq_nfq.c
    libdaq_static_modules_la_CPPFLAGS += -DBUILD_NFQ_MODULE
endif

if BUILD_NETMAP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_netmap.la
    daq_netmap_la_SOURCES = daq_netmap.c
    daq_netmap_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_netmap_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    libdaq_static_modules_la_SOURCES += daq_netmap.c
    libdaq_static_modules_la_CPPFLAGS += -DBUILD_NETMAP_MODULE
endif

if BUILD_TRACE_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_trace.la
    daq_trace_la_SOURCES = daq_trace.c
    daq_trace_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_trace_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
    daq_trace_la_LIBADD = -lpcap
endif
    libdaq_static_modules_la_SOURCES += daq_trace.c
    libdaq_static_modules_la_CPPFLAGS += -DBUILD_TRACE_MODULE
endif

AM_CPPFLAGS = @AM_CPPFLAGS@ -I$(top_srcdir)/api

EXTRA_DIST = daq-modules-config.in

CLEANFILES = daq-modules-config


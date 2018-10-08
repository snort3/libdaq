
lib_LTLIBRARIES =
pkglib_LTLIBRARIES =
pkgconfig_DATA =

if BUILD_AFPACKET_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_afpacket.la
    pkgconfig_DATA += libdaq_static_afpacket.pc
    daq_afpacket_la_SOURCES = daq_afpacket.c
    daq_afpacket_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_afpacket_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
if LIBPCAP_AVAILABLE
    daq_afpacket_la_CPPFLAGS += $(PCAP_CPPFLAGS)
    daq_afpacket_la_LDFLAGS += $(PCAP_LDFLAGS)
    daq_afpacket_la_LIBADD = $(DAQ_AFPACKET_LIBS)
endif
endif
    lib_LTLIBRARIES += libdaq_static_afpacket.la
    libdaq_static_afpacket_la_SOURCES = daq_afpacket.c
    libdaq_static_afpacket_la_CPPFLAGS = $(AM_CPPFLAGS)
    libdaq_static_afpacket_la_LDFLAGS = -static -avoid-version
if LIBPCAP_AVAILABLE
    libdaq_static_afpacket_la_CPPFLAGS += $(PCAP_CPPFLAGS)
endif
endif

if BUILD_BPF_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_bpf.la
    pkgconfig_DATA += libdaq_static_bpf.pc
    daq_bpf_la_SOURCES = daq_bpf.c
    daq_bpf_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    daq_bpf_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    daq_bpf_la_LIBADD = $(DAQ_BPF_LIBS)
endif
    lib_LTLIBRARIES += libdaq_static_bpf.la
    libdaq_static_bpf_la_SOURCES = daq_bpf.c
    libdaq_static_bpf_la_CPPFLAGS = $(AM_CPPFLAGS)
    libdaq_static_bpf_la_LDFLAGS = -static -avoid-version
endif

if BUILD_DUMP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_dump.la
    pkgconfig_DATA += libdaq_static_dump.pc
    daq_dump_la_SOURCES = daq_dump.c
    daq_dump_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    daq_dump_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    daq_dump_la_LIBADD = $(DAQ_DUMP_LIBS)
endif
    lib_LTLIBRARIES += libdaq_static_dump.la
    libdaq_static_dump_la_SOURCES = daq_dump.c
    libdaq_static_dump_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCAP_CPPFLAGS)
    libdaq_static_dump_la_LDFLAGS = -static -avoid-version
endif

if BUILD_IPFW_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_ipfw.la
    pkgconfig_DATA += libdaq_static_ipfw.pc
    daq_ipfw_la_SOURCES = daq_ipfw.c
    daq_ipfw_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_ipfw_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += libdaq_static_ipfw.la
    libdaq_static_ipfw_la_SOURCES = daq_ipfw.c
    libdaq_static_ipfw_la_CPPFLAGS = $(AM_CPPFLAGS)
    libdaq_static_ipfw_la_LDFLAGS = -static -avoid-version
endif

if BUILD_NETMAP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_netmap.la
    daq_netmap_la_SOURCES = daq_netmap.c
    daq_netmap_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_netmap_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += libdaq_static_netmap.la
    libdaq_static_netmap_la_SOURCES = daq_netmap.c
    libdaq_static_netmap_la_CPPFLAGS = $(AM_CPPFLAGS)
    libdaq_static_netmap_la_LDFLAGS = -static -avoid-version
endif

if BUILD_NFQ_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_nfq.la
    pkgconfig_DATA += libdaq_static_nfq.pc
    daq_nfq_la_SOURCES = daq_nfq.c
    daq_nfq_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_nfq_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
    daq_nfq_la_LIBADD = $(DAQ_NFQ_LIBS)
endif
    lib_LTLIBRARIES += libdaq_static_nfq.la
    libdaq_static_nfq_la_SOURCES = daq_nfq.c
    libdaq_static_nfq_la_CPPFLAGS = $(AM_CPPFLAGS)
    libdaq_static_nfq_la_LDFLAGS = -static -avoid-version
endif

if BUILD_PCAP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_pcap.la
    pkgconfig_DATA += libdaq_static_pcap.pc
    daq_pcap_la_SOURCES = daq_pcap.c
    daq_pcap_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    daq_pcap_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    daq_pcap_la_LIBADD = $(DAQ_PCAP_LIBS)
endif
    lib_LTLIBRARIES += libdaq_static_pcap.la
    libdaq_static_pcap_la_SOURCES = daq_pcap.c
    libdaq_static_pcap_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCAP_CPPFLAGS)
    libdaq_static_pcap_la_LDFLAGS = -static -avoid-version
endif

if BUILD_TRACE_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += daq_trace.la
    pkgconfig_DATA += libdaq_static_trace.pc
    daq_trace_la_SOURCES = daq_trace.c
    daq_trace_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    daq_trace_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += libdaq_static_trace.la
    libdaq_static_trace_la_SOURCES = daq_trace.c
    libdaq_static_trace_la_CPPFLAGS = $(AM_CPPFLAGS)
    libdaq_static_trace_la_LDFLAGS = -static -avoid-version
endif

AM_CPPFLAGS = @AM_CPPFLAGS@ -I$(top_srcdir)/api


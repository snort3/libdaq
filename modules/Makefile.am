AUTOMAKE_OPTIONS = subdir-objects

pkglibdir = $(libdir)/daq
lib_LTLIBRARIES =
pkglib_LTLIBRARIES =
pkgconfig_DATA =

if BUILD_AFPACKET_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += afpacket/daq_afpacket.la
    pkgconfig_DATA += afpacket/libdaq_static_afpacket.pc
    afpacket_daq_afpacket_la_SOURCES = afpacket/daq_afpacket.c
    afpacket_daq_afpacket_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    afpacket_daq_afpacket_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
if LIBPCAP_AVAILABLE
    afpacket_daq_afpacket_la_CPPFLAGS += $(PCAP_CPPFLAGS)
    afpacket_daq_afpacket_la_LDFLAGS += $(PCAP_LDFLAGS)
    afpacket_daq_afpacket_la_LIBADD = $(DAQ_AFPACKET_LIBS)
endif
endif
    lib_LTLIBRARIES += afpacket/libdaq_static_afpacket.la
    afpacket_libdaq_static_afpacket_la_SOURCES = afpacket/daq_afpacket.c
    afpacket_libdaq_static_afpacket_la_CPPFLAGS = $(AM_CPPFLAGS)
    afpacket_libdaq_static_afpacket_la_LDFLAGS = -static -avoid-version
if LIBPCAP_AVAILABLE
    afpacket_libdaq_static_afpacket_la_CPPFLAGS += $(PCAP_CPPFLAGS)
endif
endif

if BUILD_BPF_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += bpf/daq_bpf.la
    pkgconfig_DATA += bpf/libdaq_static_bpf.pc
    bpf_daq_bpf_la_SOURCES = bpf/daq_bpf.c
    bpf_daq_bpf_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    bpf_daq_bpf_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    bpf_daq_bpf_la_LIBADD = $(DAQ_BPF_LIBS)
endif
    lib_LTLIBRARIES += bpf/libdaq_static_bpf.la
    bpf_libdaq_static_bpf_la_SOURCES = bpf/daq_bpf.c
    bpf_libdaq_static_bpf_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCAP_CPPFLAGS)
    bpf_libdaq_static_bpf_la_LDFLAGS = -static -avoid-version
endif

if BUILD_DIVERT_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += divert/daq_divert.la
    pkgconfig_DATA += divert/libdaq_static_divert.pc
    divert_daq_divert_la_SOURCES = divert/daq_divert.c
    divert_daq_divert_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    divert_daq_divert_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += divert/libdaq_static_divert.la
    divert_libdaq_static_divert_la_SOURCES = divert/daq_divert.c
    divert_libdaq_static_divert_la_CPPFLAGS = $(AM_CPPFLAGS)
    divert_libdaq_static_divert_la_LDFLAGS = -static -avoid-version
endif

if BUILD_DUMP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += dump/daq_dump.la
    pkgconfig_DATA += dump/libdaq_static_dump.pc
    dump_daq_dump_la_SOURCES = dump/daq_dump.c
    dump_daq_dump_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    dump_daq_dump_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    dump_daq_dump_la_LIBADD = $(DAQ_DUMP_LIBS)
endif
    lib_LTLIBRARIES += dump/libdaq_static_dump.la
    dump_libdaq_static_dump_la_SOURCES = dump/daq_dump.c
    dump_libdaq_static_dump_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCAP_CPPFLAGS)
    dump_libdaq_static_dump_la_LDFLAGS = -static -avoid-version
endif

if BUILD_FST_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += fst/daq_fst.la
    pkgconfig_DATA += fst/libdaq_static_fst.pc
    fst_daq_fst_la_SOURCES = \
						 fst/daq_fst.cc \
						 fst/fst.h \
						 fst/PMurHash.c \
						 fst/PMurHash.h
    fst_daq_fst_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/example -DBUILDING_SO
    fst_daq_fst_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += fst/libdaq_static_fst.la
    fst_libdaq_static_fst_la_SOURCES = \
						 fst/daq_fst.cc \
						 fst/fst.h \
						 fst/PMurHash.c \
						 fst/PMurHash.h
    fst_libdaq_static_fst_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/example
    fst_libdaq_static_fst_la_LDFLAGS = -static -avoid-version
endif

if BUILD_NETMAP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += netmap/daq_netmap.la
    pkgconfig_DATA += netmap/libdaq_static_netmap.pc
    netmap_daq_netmap_la_SOURCES = netmap/daq_netmap.c
    netmap_daq_netmap_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(NETMAP_CPPFLAGS)
    netmap_daq_netmap_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += netmap/libdaq_static_netmap.la
    netmap_libdaq_static_netmap_la_SOURCES = netmap/daq_netmap.c
    netmap_libdaq_static_netmap_la_CPPFLAGS = $(AM_CPPFLAGS) $(NETMAP_CPPFLAGS)
    netmap_libdaq_static_netmap_la_LDFLAGS = -static -avoid-version
endif

if BUILD_NFQ_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += nfq/daq_nfq.la
    pkgconfig_DATA += nfq/libdaq_static_nfq.pc
    nfq_daq_nfq_la_SOURCES = nfq/daq_nfq.c
    nfq_daq_nfq_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    nfq_daq_nfq_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
    nfq_daq_nfq_la_LIBADD = $(DAQ_NFQ_LIBS)
endif
    lib_LTLIBRARIES += nfq/libdaq_static_nfq.la
    nfq_libdaq_static_nfq_la_SOURCES = nfq/daq_nfq.c
    nfq_libdaq_static_nfq_la_CPPFLAGS = $(AM_CPPFLAGS)
    nfq_libdaq_static_nfq_la_LDFLAGS = -static -avoid-version
endif

if BUILD_PCAP_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += pcap/daq_pcap.la
    pkgconfig_DATA += pcap/libdaq_static_pcap.pc
    pcap_daq_pcap_la_SOURCES = pcap/daq_pcap.c
    pcap_daq_pcap_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO $(PCAP_CPPFLAGS)
    pcap_daq_pcap_la_LDFLAGS = -module -export-dynamic -avoid-version -shared $(PCAP_LDFLAGS)
    pcap_daq_pcap_la_LIBADD = $(DAQ_PCAP_LIBS)
endif
    lib_LTLIBRARIES += pcap/libdaq_static_pcap.la
    pcap_libdaq_static_pcap_la_SOURCES = pcap/daq_pcap.c
    pcap_libdaq_static_pcap_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCAP_CPPFLAGS)
    pcap_libdaq_static_pcap_la_LDFLAGS = -static -avoid-version
endif

if BUILD_SAVEFILE_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += savefile/daq_savefile.la
    pkgconfig_DATA += savefile/libdaq_static_savefile.pc
    savefile_daq_savefile_la_SOURCES = savefile/daq_savefile.c
    savefile_daq_savefile_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    savefile_daq_savefile_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += savefile/libdaq_static_savefile.la
    savefile_libdaq_static_savefile_la_SOURCES = savefile/daq_savefile.c
    savefile_libdaq_static_savefile_la_CPPFLAGS = $(AM_CPPFLAGS)
    savefile_libdaq_static_savefile_la_LDFLAGS = -static -avoid-version
endif

if BUILD_TRACE_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += trace/daq_trace.la
    pkgconfig_DATA += trace/libdaq_static_trace.pc
    trace_daq_trace_la_SOURCES = trace/daq_trace.c
    trace_daq_trace_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    trace_daq_trace_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += trace/libdaq_static_trace.la
    trace_libdaq_static_trace_la_SOURCES = trace/daq_trace.c
    trace_libdaq_static_trace_la_CPPFLAGS = $(AM_CPPFLAGS)
    trace_libdaq_static_trace_la_LDFLAGS = -static -avoid-version
endif

if BUILD_GWLB_MODULE
if BUILD_SHARED_MODULES
    pkglib_LTLIBRARIES += gwlb/daq_gwlb.la
    pkgconfig_DATA += gwlb/libdaq_static_gwlb.pc
    gwlb_daq_gwlb_la_SOURCES = gwlb/daq_gwlb.cc
    gwlb_daq_gwlb_la_CPPFLAGS = $(AM_CPPFLAGS) -DBUILDING_SO
    gwlb_daq_gwlb_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
endif
    lib_LTLIBRARIES += gwlb/libdaq_static_gwlb.la
    gwlb_libdaq_static_gwlb_la_SOURCES = gwlb/daq_gwlb.cc
    gwlb_libdaq_static_gwlb_la_CPPFLAGS = $(AM_CPPFLAGS)
    gwlb_libdaq_static_gwlb_la_LDFLAGS = -static -avoid-version
endif

AM_CPPFLAGS = @AM_CPPFLAGS@ -I$(top_srcdir)/api


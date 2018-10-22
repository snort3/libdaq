include_HEADERS = daq.h daq_common.h daq_dlt.h daq_module_api.h daq_version.h
noinst_HEADERS = daq_api_internal.h daq_instance_api_defaults.h

lib_LTLIBRARIES = libdaq.la

libdaq_la_SOURCES = daq_base.c daq_base_api.c daq_config.c daq_instance_api_defaults.c daq_mod_ops.c
libdaq_la_CPPFLAGS = $(AM_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
libdaq_la_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
libdaq_la_LDFLAGS = $(CODE_COVERAGE_LDFLAGS) -version-info 3:0:0
libdaq_la_LIBADD = $(LIBDL)

include_HEADERS = daq.h daq_common.h daq_dlt.h daq_module_api.h daq_version.h
noinst_HEADERS = daq_api_internal.h daq_instance_api_defaults.h

lib_LTLIBRARIES = libdaq.la

libdaq_la_SOURCES = daq_base.c daq_base_api.c daq_config.c daq_instance_api_defaults.c daq_mod_ops.c
libdaq_la_CPPFLAGS = $(AM_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
libdaq_la_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
libdaq_la_LDFLAGS = $(CODE_COVERAGE_LDFLAGS) -version-info 3:0:0
libdaq_la_LIBADD = $(LIBDL)

# Convenience library for the unit tests.  The tests mock libc functions with
# ld's --wrap option, which only affects symbols resolved at static link time,
# so they must link the DAQ library statically even when configured with
# --disable-static.
check_LTLIBRARIES = libdaq_check.la
libdaq_check_la_SOURCES = $(libdaq_la_SOURCES)
libdaq_check_la_CPPFLAGS = $(libdaq_la_CPPFLAGS)
libdaq_check_la_CFLAGS = $(libdaq_la_CFLAGS)
libdaq_check_la_LIBADD = $(LIBDL)

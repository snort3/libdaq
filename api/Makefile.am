include_HEADERS = daq.h daq_api.h daq_common.h

lib_LTLIBRARIES = libdaq.la libdaq_static.la

libdaq_la_SOURCES = daq_base.c daq_config.c daq_mod_ops.c daq.h daq_api.h daq_api_common.h daq_common.h
libdaq_la_LDFLAGS = -version-info 2:4:0 @XCCFLAGS@
libdaq_la_LIBADD = @LIBDL@

libdaq_static_la_SOURCES = daq_base.c daq_config.c daq_mod_ops.c daq.h daq_api.h daq_api_common.h daq_common.h
libdaq_static_la_CFLAGS = -DSTATIC_MODULE_LIST
libdaq_static_la_LDFLAGS = -static

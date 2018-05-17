check_PROGRAMS = api_base_test api_config_test
TESTS = api_base_test api_config_test

api_base_test_SOURCES = api_base_test.c daq_test_module.c daq_test_module.h mock_stdio.c mock_stdio.h
api_base_test_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(CMOCKA_CFLAGS) -I${top_srcdir}/api
api_base_test_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(CODE_COVERAGE_LDFLAGS) \
	-static-libtool-libs \
	-Wl,--wrap,printf \
	-Wl,--wrap,__printf_chk \
	-Wl,--wrap,fprintf \
	-Wl,--wrap,__fprintf_chk \
	-Wl,--wrap,opendir \
	-Wl,--wrap,readdir \
	-Wl,--wrap,closedir \
	-Wl,--wrap,stat \
	-Wl,--wrap,__xstat \
	-Wl,--wrap,dlopen \
	-Wl,--wrap,dlsym \
	-Wl,--wrap,dlclose
api_base_test_LDADD = ${top_builddir}/api/libdaq.la $(LIBDL) $(CMOCKA_LIBS)

api_config_test_SOURCES = api_config_test.c daq_test_module.c daq_test_module.h
api_config_test_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(CMOCKA_CFLAGS) -I${top_srcdir}/api
api_config_test_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(CODE_COVERAGE_LDFLAGS) \
	-static-libtool-libs
api_config_test_LDADD = ${top_builddir}/api/libdaq.la $(LIBDL) $(CMOCKA_LIBS)

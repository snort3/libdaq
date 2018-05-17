AUTOMAKE_OPTIONS = foreign

pkgconfig_DATA = libdaq.pc

@CODE_COVERAGE_RULES@

if BUILD_MODULES
    MODULES_DIR = modules
endif
SUBDIRS = api $(MODULES_DIR) example test

ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPTIONS = foreign

include $(top_srcdir)/aminclude_static.am

pkgconfig_DATA = libdaq.pc

if BUILD_MODULES
    MODULES_DIR = modules
endif
SUBDIRS = api $(MODULES_DIR) example test

ACLOCAL_AMFLAGS = -I m4

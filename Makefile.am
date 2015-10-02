AUTOMAKE_OPTIONS = foreign

@CODE_COVERAGE_RULES@

if BUILD_MODULES
    MODULES_DIR = modules
endif
SUBDIRS = api sfbpf $(MODULES_DIR) example test

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
daq.dsp

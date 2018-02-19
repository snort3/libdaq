lib_LTLIBRARIES = libsfbpf.la

include_HEADERS = sfbpf.h sfbpf_dlt.h

libsfbpf_la_SOURCES = \
arcnet.h \
atmuni31.h \
bittypes.h \
ethertype.h \
gencode.h \
ieee80211.h \
IP6_misc.h \
ipnet.h \
llc.h \
namedb.h \
nlpid.h \
ppp.h \
sfbpf.h \
sfbpf_dlt.h \
sf-redefines.h \
sf_bpf_filter.c \
sf_bpf_printer.c \
sf_gencode.c \
sf_nametoaddr.c \
sf_optimize.c \
sfbpf-int.c \
sll.h \
sunatmpos.h

EXTRA_DIST = grammar.y scanner.l \
win32-stdinc.h \
sfbpf-int.h \
sfbpf-int.c

nodist_libsfbpf_la_SOURCES = sf_grammar.c sf_grammar.h sf_scanner.c sf_scanner.h

libsfbpf_la_CPPFLAGS = $(AM_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
libsfbpf_la_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS) -Dyylval=sfbpf_lval
libsfbpf_la_LDFLAGS = $(CODE_COVERAGE_LDFLAGS) -version-info 0:1:0

sf_scanner.c: $(srcdir)/scanner.l
	$(LEX) -P sfbpf_ --header-file=sf_scanner.h --nounput -o sf_scanner.c $<

sf_scanner.h: sf_scanner.c
	## Recover from the removal of $@
	@if test -f $@; then :; else \
		rm -f sf_scanner.c; \
		$(MAKE) $(MAKEFLAGS) sf_scanner.c; \
	fi

sf_scanner.o: sf_scanner.c sf_grammar.h

sf_grammar.c: $(srcdir)/grammar.y
	$(YACC) -p sfbpf_ -o sf_grammar.c -d $<
sf_grammar.h: sf_grammar.c
	## Recover from the removal of $@
	@if test -f $@; then :; else \
		rm -f sf_grammar.c; \
		$(MAKE) $(MAKEFLAGS) sf_grammar.c; \
	fi
sf_grammar.o: sf_grammar.c sf_scanner.h

CLEANFILES = sf_grammar.c sf_grammar.h sf_scanner.c sf_scanner.h

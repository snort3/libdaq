#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_define([daq_major_version], [3])
m4_define([daq_minor_version], [0])
m4_define([daq_patch_version], [0])
m4_define([daq_version_str], [daq_major_version.daq_minor_version.daq_patch_version])

AC_PREREQ([2.69])
AC_INIT([daq],[daq_version_str],[snort-team@sourcefire.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([api/daq.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

DAQ_MAJOR_VERSION=daq_major_version
DAQ_MINOR_VERSION=daq_minor_version
DAQ_PATCH_VERSION=daq_patch_version

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
AC_PROG_SED

LT_INIT

# Initialize pkg-config since we are installing a .pc file
PKG_INSTALLDIR

# Enable visibility if we can
gl_VISIBILITY
AM_CPPFLAGS="$AM_CPPFLAGS $CFLAG_VISIBILITY"

# Special compiler flags
if test -n "$GCC" ; then
    AX_CHECK_PREPROC_FLAG([-Wall], [AM_CPPFLAGS="$AM_CPPFLAGS -Wall"])
    AX_CHECK_PREPROC_FLAG([-Wstrict-prototypes], [AM_CPPFLAGS="$AM_CPPFLAGS -Wstrict-prototypes"])
    AX_CHECK_PREPROC_FLAG([-Wmissing-prototypes], [AM_CPPFLAGS="$AM_CPPFLAGS -Wmissing-prototypes"])
    AX_CHECK_PREPROC_FLAG([-Wmissing-declarations], [AM_CPPFLAGS="$AM_CPPFLAGS -Wmissing-declarations"])
    AX_CHECK_PREPROC_FLAG([-Wold-style-definition], [AM_CPPFLAGS="$AM_CPPFLAGS -Wold-style-definition"])
    AX_CHECK_PREPROC_FLAG([-Wpointer-arith], [AM_CPPFLAGS="$AM_CPPFLAGS -Wpointer-arith"])
    AX_CHECK_PREPROC_FLAG([-Wcast-align], [AM_CPPFLAGS="$AM_CPPFLAGS -Wcast-align"])
    AX_CHECK_PREPROC_FLAG([-Wnested-externs], [AM_CPPFLAGS="$AM_CPPFLAGS -Wnested-externs"])
    AX_CHECK_PREPROC_FLAG([-Wcast-qual], [AM_CPPFLAGS="$AM_CPPFLAGS -Wcast-qual"])
    AX_CHECK_PREPROC_FLAG([-Wformat], [AM_CPPFLAGS="$AM_CPPFLAGS -Wformat"])
    AX_CHECK_PREPROC_FLAG([-Wformat-nonliteral], [AM_CPPFLAGS="$AM_CPPFLAGS -Wformat-nonliteral"])
    AX_CHECK_PREPROC_FLAG([-Wformat-security], [AM_CPPFLAGS="$AM_CPPFLAGS -Wformat-security"])
    AX_CHECK_PREPROC_FLAG([-Wundef], [AM_CPPFLAGS="$AM_CPPFLAGS -Wundef"])
    AX_CHECK_PREPROC_FLAG([-Wwrite-strings], [AM_CPPFLAGS="$AM_CPPFLAGS -Wwrite-strings"])
    AX_CHECK_PREPROC_FLAG([-std=gnu99], [AM_CPPFLAGS="$AM_CPPFLAGS -std=gnu99"])
    AX_CHECK_PREPROC_FLAG([-Wextra], [AM_CPPFLAGS="$AM_CPPFLAGS -Wextra"])
    AX_CHECK_PREPROC_FLAG([-Wsign-compare], [AM_CPPFLAGS="$AM_CPPFLAGS -Wsign-compare"])
    AX_CHECK_PREPROC_FLAG([-Wno-unused-parameter], [AM_CPPFLAGS="$AM_CPPFLAGS -Wno-unused-parameter"])
    AX_CHECK_PREPROC_FLAG([-fno-strict-aliasing], [AM_CPPFLAGS="$AM_CPPFLAGS -fno-strict-aliasing"])
    AX_CHECK_PREPROC_FLAG([-fdiagnostics-show-option], [AM_CPPFLAGS="$AM_CPPFLAGS -fdiagnostics-show-option"])
fi

# Set up code coverage
AX_CODE_COVERAGE

# Check for cmocka
AM_CHECK_CMOCKA

# IPv6 configuration
AC_ARG_ENABLE(ipv6, 
AS_HELP_STRING([--enable-ipv6],[build IPv6-capable version @<:@default=yes, if getaddrinfo available@:>@]),
    [],
    [enable_ipv6=ifavailable])
if test "$enable_ipv6" != "no"; then
    AC_CHECK_FUNC(getaddrinfo,
        [
            AC_DEFINE(INET6,1,[System IPv6 support])
        ],
        [
            if test "$enable_ipv6" != "ifavailable"; then
                AC_MSG_FAILURE([--enable-ipv6 was given, but getaddrinfo is not available])
            fi
        ])
fi

save_LIBS=${LIBS}

# Checks for libraries.
AC_ARG_WITH(libpcap_includes,
            [  --with-libpcap-includes=DIR    libpcap include directory],
            [with_pcap_includes="$withval"], [with_pcap_includes="no"])

AC_ARG_WITH(libpcap_libraries,
            [  --with-libpcap-libraries=DIR   libpcap library directory],
            [with_pcap_libraries="$withval"], [with_pcap_libraries="no"])

if test "x$with_pcap_includes" != "xno"; then
    PCAP_CPPFLAGS="-I${with_pcap_includes}"
fi

if test "x$with_pcap_libraries" != "xno"; then
    PCAP_LDFLAGS="-L${with_pcap_libraries}"
fi

# Check to see if libpcap is available to be used by modules
save_CPPFLAGS="$CPPFLAGS"
save_LDFLAGS="$LDFLAGS"
CPPFLAGS="$PCAP_CPPFLAGS $CPPFLAGS"
LDFLAGS="$PCAP_LDFLAGS $LDFLAGS"
AC_CHECK_HEADER([pcap.h], [HAVE_PCAP_HEADERS=yes])
AC_CHECK_LIB([pcap],[pcap_lib_version], [HAVE_PCAP_LIBRARY=yes])
CPPFLAGS="$save_CPPFLAGS"
LDFLAGS="$save_LDFLAGS"
if test "x$HAVE_PCAP_HEADERS" = "xyes" -a "x$HAVE_PCAP_LIBRARY" = "xyes" ; then
    LIBPCAP_AVAILABLE=yes
    AC_DEFINE(LIBPCAP_AVAILABLE,1,[Define to 1 if libPCAP is available for use.])
fi
AM_CONDITIONAL([LIBPCAP_AVAILABLE], [test "$LIBPCAP_AVAILABLE" = yes])

#AC_ARG_WITH(dnet_includes,
#            [  --with-dnet-includes=DIR    dnet include directory],
#            [with_dnet_includes="$withval"], [with_dnet_includes="no"])
#
#AC_ARG_WITH(dnet_libraries,
#            [  --with-dnet-libraries=DIR   dnet library directory],
#            [with_dnet_libraries="$withval"], [with_dnet_libraries="no"])
#
#if test "x$with_dnet_includes" != "xno"; then
#    DNET_CPPFLAGS="-I${with_dnet_includes}"
#else
#    DNET_CPPFLAGS="`dnet-config --cflags 2>/dev/null`"
#fi
#
#if test "x$with_dnet_libraries" != "xno"; then
#    DNET_LDFLAGS="-L${with_dnet_libraries}"
#else
#    DNET_LDFLAGS="`dnet-config --libs 2>/dev/null`"
#fi

AC_ARG_WITH(netmap_includes,
            [  --with-netmap-includes=DIR    netmap include directory],
            [with_netmap_includes="$withval"], [with_netmap_includes="no"])

if test "x$with_netmap_includes" != "xno"; then
    NETMAP_CPPFLAGS="-I${with_netmap_includes}"
fi

DEFAULT_ENABLE=yes

# Modules configuration
AC_ARG_ENABLE(bundled-modules,
              AS_HELP_STRING([--disable-bundled-modules],[do not build any of the bundled DAQ modules by default]),
              [], [disable_bundled_modules=no])

if test "$disable_bundled_modules" = no; then
    DEFAULT_ENABLE=yes
else
    DEFAULT_ENABLE=no
fi

# AFPacket Module
AC_ARG_ENABLE(afpacket-module,
              AS_HELP_STRING([--disable-afpacket-module],[do not build the bundled AFPacket module]),
              [enable_afpacket_module="$enableval"], [enable_afpacket_module="$DEFAULT_ENABLE"])
if test "$enable_afpacket_module" = yes; then
    AC_CHECK_HEADERS([linux/if_ether.h linux/if_packet.h], [], [enable_afpacket_module=no])
    AC_CHECK_DECLS([TPACKET2_HDRLEN, PACKET_TX_RING], [], [enable_afpacket_module=no], [[#include <linux/if_packet.h>]])
    if test "$enable_afpacket_module" = yes -a "$LIBPCAP_AVAILABLE" = yes ; then
        DAQ_AFPACKET_LIBS="-lpcap -lpthread"
    fi
fi
AM_CONDITIONAL([BUILD_AFPACKET_MODULE], [test "$enable_afpacket_module" = yes])
AM_COND_IF([BUILD_AFPACKET_MODULE], [AC_CONFIG_FILES([modules/afpacket/libdaq_static_afpacket.pc])])

# BPF Wrapper Module
AC_ARG_ENABLE(bpf-module,
              AS_HELP_STRING([--disable-bpf-module],[do not build the bundled BPF wrapper module]),
              [enable_bpf_module="$enableval"], [enable_bpf_module="$DEFAULT_ENABLE"])
if test "$enable_bpf_module" = yes; then
    if test "$LIBPCAP_AVAILABLE" = yes ; then
        DAQ_BPF_LIBS="-lpcap -lpthread"
    else
        AC_MSG_WARN([LibPCAP not available, disabling the BPF DAQ module])
        enable_bpf_module=no
    fi
fi
AM_CONDITIONAL([BUILD_BPF_MODULE], [test "$enable_bpf_module" = yes])
AM_COND_IF([BUILD_BPF_MODULE], [AC_CONFIG_FILES([modules/bpf/libdaq_static_bpf.pc])])

# Dump Module
AC_ARG_ENABLE(dump-module,
              AS_HELP_STRING([--disable-dump-module],[do not build the bundled Dump module]),
              [enable_dump_module="$enableval"], [enable_dump_module="$DEFAULT_ENABLE"])
if test "$enable_dump_module" = yes; then
    if test "$LIBPCAP_AVAILABLE" = yes ; then
        DAQ_DUMP_LIBS="-lpcap"
    else
        AC_MSG_WARN([LibPCAP not available, disabling the Dump DAQ module])
        enable_dump_module=no
    fi
fi
AM_CONDITIONAL([BUILD_DUMP_MODULE], [test "$enable_dump_module" = yes])
AM_COND_IF([BUILD_DUMP_MODULE], [AC_CONFIG_FILES([modules/dump/libdaq_static_dump.pc])])

# IPFW Module
AC_ARG_ENABLE(ipfw-module,
              AS_HELP_STRING([--disable-ipfw-module],[do not build the bundled IPFW module]),
              [enable_ipfw_module="$enableval"], [enable_ipfw_module="$DEFAULT_ENABLE"])
if test "$enable_ipfw_module" = yes; then
    AC_CHECK_DECLS([IPPROTO_DIVERT], [], [enable_ipfw_module=no], [[#include <netinet/in.h>]])
fi
AM_CONDITIONAL([BUILD_IPFW_MODULE], [test "$enable_ipfw_module" = yes])
AM_COND_IF([BUILD_IPFW_MODULE], [AC_CONFIG_FILES([modules/ipfw/libdaq_static_ipfw.pc])])

# NFQ Module
AC_ARG_ENABLE(nfq-module,
              AS_HELP_STRING([--disable-nfq-module],[do not build the bundled NFQ module]),
              [enable_nfq_module="$enableval"], [enable_nfq_module="$DEFAULT_ENABLE"])
if test "$enable_nfq_module" = yes; then
    AC_CHECK_HEADERS([linux/netfilter.h linux/netfilter/nfnetlink_queue.h libmnl/libmnl.h], [], [enable_nfq_module=no])
    AC_CHECK_LIB([mnl], [mnl_socket_open], [], [enable_nfq_module=no])
    if test "$enable_nfq_module" = yes; then
        DAQ_NFQ_LIBS="-lmnl"
    fi
fi
AM_CONDITIONAL([BUILD_NFQ_MODULE], [test "$enable_nfq_module" = yes])
AM_COND_IF([BUILD_NFQ_MODULE], [AC_CONFIG_FILES([modules/nfq/libdaq_static_nfq.pc])])

# PCAP Module
AC_ARG_ENABLE(pcap-module,
              AS_HELP_STRING([--disable-pcap-module],[do not build the bundled PCAP module]),
              [enable_pcap_module="$enableval"], [enable_pcap_module="$DEFAULT_ENABLE"])
if test "$enable_pcap_module" = yes; then
    if test "$LIBPCAP_AVAILABLE" = yes ; then
        DAQ_PCAP_LIBS="-lpcap -lpthread"
    else
        AC_MSG_WARN([LibPCAP not available, disabling the PCAP DAQ module])
        enable_pcap_module=no
    fi
fi
AM_CONDITIONAL([BUILD_PCAP_MODULE], [test "$enable_pcap_module" = yes])
AM_COND_IF([BUILD_PCAP_MODULE], [AC_CONFIG_FILES([modules/pcap/libdaq_static_pcap.pc])])

# netmap Module
#AC_ARG_ENABLE(netmap-module,
#              AS_HELP_STRING([--disable-netmap-module],[do not build the bundled netmap module]),
#              [enable_netmap_module="$enableval"], [enable_netmap_module="$DEFAULT_ENABLE"])
#if test "$enable_netmap_module" = yes; then
#    AC_CHECK_HEADERS([net/netmap.h net/netmap_user.h], [], [enable_netmap_module=no], [
#                      #include <stdint.h>
#                      #include <sys/socket.h>
#                      #include <net/if.h>
#                      ])
#    AC_CHECK_DECL([NETMAP_API], [], [enable_netmap_module=no], [
#                   #include <stdint.h>
#                   #include <sys/socket.h>
#                   #include <net/if.h>
#                   #include <net/netmap.h>
#                   ])
#fi
AM_CONDITIONAL([BUILD_NETMAP_MODULE], [test "$enable_netmap_module" = yes])

#if test "$enable_nfq_module" = yes ; then
#    AC_CHECK_HEADERS(dnet.h,,DNET_H="no")
#    AC_CHECK_HEADERS(dumbnet.h,,DUMBNET_H="no")
#
#    if test "x$DNET_H" = "xno" -a "x$DUMBNET_H" = "xno"; then
#        echo
#        echo "   ERROR!  dnet header not found, go get it from"
#        echo "   http://code.google.com/p/libdnet/ or use the --with-dnet-*"
#        echo "   options, if you have it installed in an unusual place"
#        exit
#    fi
#
#    DNET_FOO="${DNET_LDFLAGS}"
#
#    AC_CHECK_LIB(dnet, eth_set, ,[DNET="no"], [${DNET_FOO}])
#    AC_CHECK_LIB(dumbnet, eth_set, ,[DUMBNET="no"], [${DNET_FOO}])
#
#    if test "x$DNET" = "xno" -a "x$DUMBNET" = "xno"; then
#        echo
#        echo "   ERROR!  dnet library not found, go get it from"
#        echo "   http://code.google.com/p/libdnet/ or use the --with-dnet-*"
#        echo "   options, if you have it installed in an unusual place"
#        exit
#    fi
#
#    if test "x$DNET_LDFLAGS" = "x" ; then
#        if test "x$DNET" = "xno"; then
#            DNET_LDFLAGS="${DNET_LDPATH} -ldumbnet"
#        else
#            DNET_LDFLAGS="${DNET_LDPATH} -ldnet"
#        fi
#    fi
#    #echo "DNET_LDFLAGS=${DNET_LDFLAGS}"
#    STATIC_LIBS="${STATIC_LIBS} ${DNET_LDFLAGS}"
#fi

# Trace Module
AC_ARG_ENABLE(trace-module,
              AS_HELP_STRING([--disable-trace-module],[do not build the bundled Trace module]),
              [enable_trace_module="$enableval"], [enable_trace_module="$DEFAULT_ENABLE"])
AM_CONDITIONAL([BUILD_TRACE_MODULE], [test "$enable_trace_module" = yes])
AM_COND_IF([BUILD_TRACE_MODULE], [AC_CONFIG_FILES([modules/trace/libdaq_static_trace.pc])])

#AC_SUBST(DNET_LDFLAGS)

AM_CONDITIONAL([BUILD_MODULES], [test "$enable_afpacket_module" = yes -o \
                                      "$enable_bpf_module" = yes -o \
                                      "$enable_dump_module" = yes -o \
                                      "$enable_ipfw_module" = yes -o \
                                      "$enable_nfq_module" = yes -o \
                                      "$enable_pcap_module" = yes -o \
                                      "$enable_trace_module" = yes])

LIBS=${save_LIBS}

AC_CHECK_LIB([dl], [dlopen], [LIBDL="-ldl"])

AM_CONDITIONAL([BUILD_SHARED_MODULES], [ test "$enable_shared" = yes ])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h memory.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([gethostbyname getpagesize memset munmap socket strchr strcspn strdup strerror strrchr strstr strtoul])

# Substitutions
AC_SUBST(LIBDL)
AC_SUBST(AM_CPPFLAGS)
AC_SUBST(CFLAGS)
AC_SUBST(DAQ_MAJOR_VERSION)
AC_SUBST(DAQ_MINOR_VERSION)
AC_SUBST(DAQ_PATCH_VERSION)
AC_SUBST(PCAP_CPPFLAGS)
AC_SUBST(PCAP_LDFLAGS)

# Module-specific Substitutions
AC_SUBST(DAQ_AFPACKET_LIBS)
AC_SUBST(DAQ_BPF_LIBS)
AC_SUBST(DAQ_DUMP_LIBS)
AC_SUBST(DAQ_NFQ_LIBS)
AC_SUBST(DAQ_PCAP_LIBS)

if test "${CODE_COVERAGE_ENABLED}" = yes ; then
    CFLAGS=`echo $CFLAGS | ${SED} 's/-O\w//g'`
fi

AC_CONFIG_FILES([Makefile
                 api/daq_version.h
                 api/Makefile
                 example/Makefile
                 modules/Makefile
                 test/Makefile
                 libdaq.pc
                 ])
AC_OUTPUT

AC_MSG_RESULT([
    $PACKAGE $VERSION

    prefix:         ${prefix}
    sysconfdir:     ${sysconfdir}
    libdir:         ${libdir}
    includedir:     ${includedir}

    cc:             ${CC}
    cppflags:       ${CPPFLAGS}
    am_cppflags:    ${AM_CPPFLAGS}
    cflags:         ${CFLAGS}
    am_cflags:      ${AM_CFLAGS}
    ldflags:        ${LDFLAGS}
    am_ldflags:     ${AM_LDFLAGS}
    libs:           ${LIBS}

    code_coverage_enabled:  ${CODE_COVERAGE_ENABLED}
    code_coverage_cppflags: ${CODE_COVERAGE_CPPFLAGS}
    code_coverage_cflags:   ${CODE_COVERAGE_CFLAGS}
    code_coverage_ldflags:  ${CODE_COVERAGE_LDFLAGS}

    Build AFPacket DAQ module.. : $enable_afpacket_module
    Build BPF DAQ module....... : $enable_bpf_module
    Build Dump DAQ module...... : $enable_dump_module
    Build IPFW DAQ module...... : $enable_ipfw_module
    Build NFQ DAQ module....... : $enable_nfq_module
    Build PCAP DAQ module...... : $enable_pcap_module
    Build netmap DAQ module.... : $enable_netmap_module
    Build Trace DAQ module..... : $enable_trace_module
])

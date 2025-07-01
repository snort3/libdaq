#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_define([daq_major_version], [3])
m4_define([daq_minor_version], [0])
m4_define([daq_patch_version], [20])
m4_define([daq_version_str], [daq_major_version.daq_minor_version.daq_patch_version])

# Kill the 'divert' macro with extreme prejudice so it stops clashing with references
# to the module directory of the same name.
# TODO: Find the "right" way to escape this macro in arguments to m4 functions.
m4_undefine([divert])

AC_PREREQ([2.69])
AC_INIT([libdaq],[daq_version_str],[snort-team@cisco.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([api/daq.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability])

DAQ_MAJOR_VERSION=daq_major_version
DAQ_MINOR_VERSION=daq_minor_version
DAQ_PATCH_VERSION=daq_patch_version

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CXX
AM_PROG_AR
AC_PROG_SED

AX_CXX_COMPILE_STDCXX_11(,optional)

LT_INIT

# Initialize pkg-config since we are installing a .pc file
PKG_INSTALLDIR

# Enable visibility if we can
gl_VISIBILITY
AM_CPPFLAGS="$AM_CPPFLAGS $CFLAG_VISIBILITY"

# Special compiler flags
if test -n "$GCC" ; then
    AX_CHECK_PREPROC_FLAG([-Wall], [AM_CPPFLAGS="$AM_CPPFLAGS -Wall"])
    AX_CHECK_PREPROC_FLAG([-Wmissing-declarations], [AM_CPPFLAGS="$AM_CPPFLAGS -Wmissing-declarations"])
    AX_CHECK_PREPROC_FLAG([-Wpointer-arith], [AM_CPPFLAGS="$AM_CPPFLAGS -Wpointer-arith"])
    AX_CHECK_PREPROC_FLAG([-Wcast-align], [AM_CPPFLAGS="$AM_CPPFLAGS -Wcast-align"])
    AX_CHECK_PREPROC_FLAG([-Wcast-qual], [AM_CPPFLAGS="$AM_CPPFLAGS -Wcast-qual"])
    AX_CHECK_PREPROC_FLAG([-Wformat], [AM_CPPFLAGS="$AM_CPPFLAGS -Wformat"])
    AX_CHECK_PREPROC_FLAG([-Wformat-nonliteral], [AM_CPPFLAGS="$AM_CPPFLAGS -Wformat-nonliteral"])
    AX_CHECK_PREPROC_FLAG([-Wformat-security], [AM_CPPFLAGS="$AM_CPPFLAGS -Wformat-security"])
    AX_CHECK_PREPROC_FLAG([-Wundef], [AM_CPPFLAGS="$AM_CPPFLAGS -Wundef"])
    AX_CHECK_PREPROC_FLAG([-Wwrite-strings], [AM_CPPFLAGS="$AM_CPPFLAGS -Wwrite-strings"])
    AX_CHECK_PREPROC_FLAG([-Wextra], [AM_CPPFLAGS="$AM_CPPFLAGS -Wextra"])
    AX_CHECK_PREPROC_FLAG([-Wsign-compare], [AM_CPPFLAGS="$AM_CPPFLAGS -Wsign-compare"])
    AX_CHECK_PREPROC_FLAG([-Wno-unused-parameter], [AM_CPPFLAGS="$AM_CPPFLAGS -Wno-unused-parameter"])
    AX_CHECK_PREPROC_FLAG([-fno-strict-aliasing], [AM_CPPFLAGS="$AM_CPPFLAGS -fno-strict-aliasing"])
    AX_CHECK_PREPROC_FLAG([-fdiagnostics-show-option], [AM_CPPFLAGS="$AM_CPPFLAGS -fdiagnostics-show-option"])
    # C-only warnings
    AX_CHECK_PREPROC_FLAG([-Wstrict-prototypes], [AM_CFLAGS="$AM_CFLAGS -Wstrict-prototypes"])
    AX_CHECK_PREPROC_FLAG([-Wmissing-prototypes], [AM_CFLAGS="$AM_CFLAGS -Wmissing-prototypes"])
    AX_CHECK_PREPROC_FLAG([-Wold-style-definition], [AM_CFLAGS="$AM_CFLAGS -Wold-style-definition"])
    AX_CHECK_PREPROC_FLAG([-Wnested-externs], [AM_CFLAGS="$AM_CFLAGS -Wnested-externs"])
fi

# Set up code coverage
AX_CODE_COVERAGE

# Check for cmocka
AM_CHECK_CMOCKA

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
    # AKA check for Linux 3.14
    AC_CHECK_DECLS([PACKET_FANOUT_QM, PACKET_QDISC_BYPASS, TP_STATUS_VLAN_TPID_VALID], [],
                   [enable_afpacket_module=no], [[#include <linux/if_packet.h>]])
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

# Divert Module
AC_ARG_ENABLE(divert-module,
              AS_HELP_STRING([--disable-divert-module],[do not build the bundled Divert module]),
              [enable_divert_module="$enableval"], [enable_divert_module="$DEFAULT_ENABLE"])
if test "$enable_divert_module" = yes; then
    AC_CHECK_DECLS([IPPROTO_DIVERT], [], [enable_divert_module=no], [[#include <netinet/in.h>]])
fi
AM_CONDITIONAL([BUILD_DIVERT_MODULE], [test "$enable_divert_module" = yes])
AM_COND_IF([BUILD_DIVERT_MODULE], [AC_CONFIG_FILES([modules/divert/libdaq_static_divert.pc])])

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

# FST Module
AC_ARG_ENABLE(fst-module,
              AS_HELP_STRING([--disable-fst-module],[do not build the bundled FST module]),
              [enable_fst_module="$enableval"], [enable_fst_module="$DEFAULT_ENABLE"])
if test "$enable_fst_module" = yes; then
    if test "$HAVE_CXX11" = 1 ; then
        DAQ_FST_LIBS="-lstdc++"
        case "${host_os}" in
            # Clang on *BSD isn't smart enough to link us with libm when we use ceilf in STL
            freebsd*|openbsd*)
                DAQ_FST_LIBS="$DAQ_FST_LIBS -lm"
                ;;
        esac
    else
        AC_MSG_WARN([A compiler with C++11 support is not available, disabling the FST DAQ module])
        enable_fst_module=no
    fi
fi
AM_CONDITIONAL([BUILD_FST_MODULE], [test "$enable_fst_module" = yes])
AM_COND_IF([BUILD_FST_MODULE], [AC_CONFIG_FILES([modules/fst/libdaq_static_fst.pc])])

# Netmap Module
AC_ARG_ENABLE(netmap-module,
              AS_HELP_STRING([--disable-netmap-module],[do not build the bundled netmap module]),
              [enable_netmap_module="$enableval"], [enable_netmap_module="$DEFAULT_ENABLE"])
if test "$enable_netmap_module" = yes; then
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$NETMAP_CPPFLAGS $CPPFLAGS"
    AC_CHECK_HEADERS([net/netmap.h net/netmap_user.h], [], [enable_netmap_module=no], [
                      #include <stdint.h>
                      #include <net/if.h>
                      ])
    AC_CHECK_DECL([NETMAP_API], [], [enable_netmap_module=no], [
                   #include <stdint.h>
                   #include <net/if.h>
                   #include <net/netmap.h>
                   ])
    CPPFLAGS="$save_CPPFLAGS"
fi
AM_CONDITIONAL([BUILD_NETMAP_MODULE], [test "$enable_netmap_module" = yes])
AM_COND_IF([BUILD_NETMAP_MODULE], [AC_CONFIG_FILES([modules/netmap/libdaq_static_netmap.pc])])

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

# Savefile Module
AC_ARG_ENABLE(savefile-module,
              AS_HELP_STRING([--disable-savefile-module],[do not build the bundled Savefile module]),
              [enable_savefile_module="$enableval"], [enable_savefile_module="$DEFAULT_ENABLE"])
AM_CONDITIONAL([BUILD_SAVEFILE_MODULE], [test "$enable_savefile_module" = yes])
AM_COND_IF([BUILD_SAVEFILE_MODULE], [AC_CONFIG_FILES([modules/savefile/libdaq_static_savefile.pc])])

# Trace Module
AC_ARG_ENABLE(trace-module,
              AS_HELP_STRING([--disable-trace-module],[do not build the bundled Trace module]),
              [enable_trace_module="$enableval"], [enable_trace_module="$DEFAULT_ENABLE"])
AM_CONDITIONAL([BUILD_TRACE_MODULE], [test "$enable_trace_module" = yes])
AM_COND_IF([BUILD_TRACE_MODULE], [AC_CONFIG_FILES([modules/trace/libdaq_static_trace.pc])])

# GWLB Module
AC_ARG_ENABLE(gwlb-module,
              AS_HELP_STRING([--disable-gwlb-module],[do not build the bundled GWLB module]),
              [enable_gwlb_module="$enableval"], [enable_gwlb_module="$DEFAULT_ENABLE"])
if test "$enable_gwlb_module" = yes -a "$enable_afpacket_module" != yes; then
    enable_gwlb_module=no
fi
AM_CONDITIONAL([BUILD_GWLB_MODULE], [test "$enable_gwlb_module" = yes])
AM_COND_IF([BUILD_GWLB_MODULE], [AC_CONFIG_FILES([modules/gwlb/libdaq_static_gwlb.pc])])

#AC_SUBST(DNET_LDFLAGS)

AM_CONDITIONAL([BUILD_MODULES], [test "$enable_afpacket_module" = yes -o \
                                      "$enable_bpf_module" = yes -o \
                                      "$enable_divert_module" = yes -o \
                                      "$enable_dump_module" = yes -o \
                                      "$enable_fst_module" = yes -o \
                                      "$enable_nfq_module" = yes -o \
                                      "$enable_pcap_module" = yes -o \
                                      "$enable_trace_module" = yes -o \
                                      "$enable_gwlb_module" = yes])

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
AC_SUBST(AM_CFLAGS)
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
AC_SUBST(DAQ_FST_LIBS)
AC_SUBST(DAQ_NFQ_LIBS)
AC_SUBST(DAQ_PCAP_LIBS)
AC_SUBST(NETMAP_CPPFLAGS)

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
    Build Divert DAQ module.... : $enable_divert_module
    Build Dump DAQ module...... : $enable_dump_module
    Build FST DAQ module....... : $enable_fst_module
    Build netmap DAQ module.... : $enable_netmap_module
    Build NFQ DAQ module....... : $enable_nfq_module
    Build PCAP DAQ module...... : $enable_pcap_module
    Build Savefile DAQ module.. : $enable_savefile_module
    Build Trace DAQ module..... : $enable_trace_module
    Build GWLB DAQ module...... : $enable_gwlb_module
])

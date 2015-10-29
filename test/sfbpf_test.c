#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include "sfbpf.h"

static const char *filter_strings[] = 
{
    "host 192.168.1.1",
    "port 80",
    "tcp[tcpflags]&tcp-syn != 0 or tcp[tcpflags]&tcp-fin != 0 or tcp[tcpflags]&tcp-rst != 0",
    "ether[12:2] = 0x800 or ether[12:2] = 0x8100 or ether[0] & 0x80 != 0 or ether[12:2] = 0x9100",
    "vlan 186 and ip",
    "ip and ((icmp and dst host 1.1.1.1 and not host 2.2.2.2) or (host 1.1.1.1 and src host 3.3.3.3))",
    "not vlan and tcp port 80",
    NULL
};

static void test_sfbpf_filters(void **state)
{
    const char **filter_string;
    struct sfbpf_program fcode;
    int rval;

    for (filter_string = filter_strings; *filter_string; filter_string++)
    {
        rval = sfbpf_compile(65535, DLT_EN10MB, &fcode, *filter_string, 1, 0);
        assert_int_equal(rval, 0);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sfbpf_filters),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

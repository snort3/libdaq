/*
** Copyright (C) 2018-2026 Cisco and/or its affiliates. All rights reserved.
** Author: Priyanka Gurudev <prbg@cisco.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

#include "daq_version.h"

static void test_version_macros_defined(void **state)
{
    (void) state;

    assert_true(DAQ_VERSION_MAJOR >= 0);
    assert_true(DAQ_VERSION_MINOR >= 0);
    assert_true(DAQ_VERSION_PATCH >= 0);
    assert_true(DAQ_VERSION_SUBLEVEL >= 0);
}

static void test_version_numeric(void **state)
{
    (void) state;

    uint32_t expected = (DAQ_VERSION_MAJOR << 24) | (DAQ_VERSION_MINOR << 16) |
                        (DAQ_VERSION_PATCH << 8) | DAQ_VERSION_SUBLEVEL;
    assert_int_equal(DAQ_VERSION_NUMERIC, expected);

    assert_int_equal((DAQ_VERSION_NUMERIC >> 24) & 0xFF, DAQ_VERSION_MAJOR);
    assert_int_equal((DAQ_VERSION_NUMERIC >> 16) & 0xFF, DAQ_VERSION_MINOR);
    assert_int_equal((DAQ_VERSION_NUMERIC >> 8) & 0xFF, DAQ_VERSION_PATCH);
    assert_int_equal(DAQ_VERSION_NUMERIC & 0xFF, DAQ_VERSION_SUBLEVEL);
}

static void test_version_string(void **state)
{
    (void) state;

    char expected[32];
    snprintf(expected, sizeof(expected), "%d.%d.%d.%d",
             DAQ_VERSION_MAJOR, DAQ_VERSION_MINOR,
             DAQ_VERSION_PATCH, DAQ_VERSION_SUBLEVEL);

    assert_string_equal(DAQ_VERSION_STRING, expected);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_version_macros_defined),
        cmocka_unit_test(test_version_numeric),
        cmocka_unit_test(test_version_string),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

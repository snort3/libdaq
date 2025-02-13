/*
** Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
** Author: Michael R. Altizer <mialtize@cisco.com>
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

#include <cmocka.h>

#include "daq.h"

#include "daq_test_module.h"

static const DAQ_ModuleAPI_t *static_modules[] = 
{
    &test_module,
    NULL
};

static void test_no_config(void **state)
{
    int rval;

    rval = daq_config_new(NULL);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    rval = daq_config_push_module_config(NULL, NULL);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_null(daq_config_pop_module_config(NULL));
    
    assert_null(daq_config_top_module_config(NULL));

    assert_null(daq_config_next_module_config(NULL));
}

static void test_no_module_config(void **state)
{
    assert_null(daq_module_config_get_module(NULL));

    assert_null(daq_module_config_get_next(NULL));
}

static int daq_config_bringup(void **state)
{
    DAQ_ModuleConfig_h modcfg;
    DAQ_Config_h cfg;
    DAQ_Module_h module;
    int rval;

    if (daq_config_new(&cfg) != DAQ_SUCCESS)
        return -1;

    module = daq_find_module(TEST_MODULE_NAME);
    if (!module)
        return -1;

    rval = daq_module_config_new(&modcfg, module);
    if (rval != DAQ_SUCCESS)
        return -1;

    rval = daq_config_push_module_config(cfg, modcfg);
    if (rval != DAQ_SUCCESS)
        return -1;

    *state = cfg;
    return 0;
}

static int daq_config_teardown(void **state)
{
    DAQ_Config_h config = (DAQ_Config_h) *state;
    daq_config_destroy(config);
    return 0;
}

#define TEST_INPUT_STRING   "input"
#define TEST_INPUT_STRING2  "input2"
static void test_input(void **state)
{
    DAQ_Config_h cfg = *state;
    int rval;

    /* NULL config test */
    rval = daq_config_set_input(NULL, TEST_INPUT_STRING);
    assert_int_equal(rval, DAQ_ERROR_INVAL);
    assert_null(daq_config_get_input(NULL));

    /* Fresh configuration */
    assert_null(daq_config_get_input(cfg));

    /* Set and get */
    rval = daq_config_set_input(cfg, TEST_INPUT_STRING);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_string_equal(daq_config_get_input(cfg), TEST_INPUT_STRING);

    rval = daq_config_set_input(cfg, TEST_INPUT_STRING2);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_string_equal(daq_config_get_input(cfg), TEST_INPUT_STRING2);
}

#define TEST_SNAPLEN    1337
static void test_snaplen(void **state)
{
    DAQ_Config_h cfg = *state;
    int rval;

    /* NULL config test */
    rval = daq_config_set_snaplen(NULL, TEST_SNAPLEN);
    assert_int_equal(rval, DAQ_ERROR_INVAL);
    assert_int_equal(daq_config_get_snaplen(NULL), 0);

    /* Fresh configuration */
    assert_int_equal(daq_config_get_snaplen(cfg), 0);

    /* Set and get */
    rval = daq_config_set_snaplen(cfg, TEST_SNAPLEN);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_int_equal(daq_config_get_snaplen(cfg), TEST_SNAPLEN);
}

#define TEST_TIMEOUT    1337
static void test_timeout(void **state)
{
    DAQ_Config_h cfg = *state;
    int rval;

    /* NULL config test */
    rval = daq_config_set_timeout(NULL, TEST_TIMEOUT);
    assert_int_equal(rval, DAQ_ERROR_INVAL);
    assert_int_equal(daq_config_get_timeout(NULL), 0);

    /* Fresh configuration */
    assert_int_equal(daq_config_get_timeout(cfg), 0);

    /* Set and get */
    rval = daq_config_set_timeout(cfg, TEST_TIMEOUT);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_int_equal(daq_config_get_timeout(cfg), TEST_TIMEOUT);
}

static void test_module_mode(void **state)
{
    DAQ_Config_h cfg = *state;
    DAQ_ModuleConfig_h modcfg;
    int rval;

    modcfg = daq_config_top_module_config(cfg);
    assert_non_null(modcfg);

    /* NULL config test */
    rval = daq_module_config_set_mode(NULL, DAQ_MODE_PASSIVE);
    assert_int_equal(rval, DAQ_ERROR_INVAL);
    assert_int_equal(daq_module_config_get_mode(NULL), DAQ_MODE_NONE);

    /* Fresh configuration */
    assert_int_equal(daq_module_config_get_mode(modcfg), DAQ_MODE_NONE);

    /* Set and get */
    rval = daq_module_config_set_mode(modcfg, DAQ_MODE_PASSIVE);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_int_equal(daq_module_config_get_mode(modcfg), DAQ_MODE_PASSIVE);

    rval = daq_module_config_set_mode(modcfg, DAQ_MODE_INLINE);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_int_equal(daq_module_config_get_mode(modcfg), DAQ_MODE_INLINE);

    rval = daq_module_config_set_mode(modcfg, DAQ_MODE_READ_FILE);
    assert_int_equal(rval, DAQ_ERROR_INVAL);
    assert_int_equal(daq_module_config_get_mode(modcfg), DAQ_MODE_INLINE);
}

#define TEST_VARIABLE_KEY       "key"
#define TEST_VARIABLE_KEY2      "key2"
#define TEST_VARIABLE_VALUE     "value"
#define TEST_VARIABLE_VALUE2    "value2"
static void test_module_variables(void **state)
{
    DAQ_Config_h cfg = *state;
    DAQ_ModuleConfig_h modcfg;
    const char *key, *value;
    int rval;

    modcfg = daq_config_top_module_config(cfg);
    assert_non_null(modcfg);

    /* NULL config test */
    rval = daq_module_config_set_variable(NULL, TEST_VARIABLE_KEY, TEST_VARIABLE_VALUE);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_null(daq_module_config_get_variable(NULL, TEST_VARIABLE_KEY));

    rval = daq_module_config_delete_variable(NULL, TEST_VARIABLE_KEY);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    rval = daq_module_config_first_variable(NULL, &key, &value);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    rval = daq_module_config_next_variable(NULL, &key, &value);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    daq_module_config_clear_variables(NULL);

    /* Fresh configuration */
    rval = daq_module_config_first_variable(modcfg, &key, &value);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_null(key);
    assert_null(value);

    /* Set and get */
    rval = daq_module_config_set_variable(modcfg, TEST_VARIABLE_KEY, TEST_VARIABLE_VALUE);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_string_equal(daq_module_config_get_variable(modcfg, TEST_VARIABLE_KEY), TEST_VARIABLE_VALUE);

    rval = daq_module_config_set_variable(modcfg, TEST_VARIABLE_KEY, NULL);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_null(daq_module_config_get_variable(modcfg, TEST_VARIABLE_KEY));

    rval = daq_module_config_set_variable(modcfg, TEST_VARIABLE_KEY, TEST_VARIABLE_VALUE2);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_string_equal(daq_module_config_get_variable(modcfg, TEST_VARIABLE_KEY), TEST_VARIABLE_VALUE2);

    rval = daq_module_config_set_variable(modcfg, TEST_VARIABLE_KEY2, NULL);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_null(daq_module_config_get_variable(modcfg, TEST_VARIABLE_KEY2));

    rval = daq_module_config_first_variable(modcfg, &key, &value);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_string_equal(key, TEST_VARIABLE_KEY2);
    assert_null(value);

    rval = daq_module_config_next_variable(modcfg, &key, &value);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_string_equal(key, TEST_VARIABLE_KEY);
    assert_string_equal(value, TEST_VARIABLE_VALUE2);

    rval = daq_module_config_next_variable(modcfg, &key, &value);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_null(key);
    assert_null(value);

    rval = daq_module_config_delete_variable(modcfg, TEST_VARIABLE_KEY);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_null(daq_module_config_get_variable(modcfg, TEST_VARIABLE_KEY));

    rval = daq_module_config_delete_variable(modcfg, TEST_VARIABLE_KEY2);
    assert_int_equal(rval, DAQ_SUCCESS);

    rval = daq_module_config_delete_variable(modcfg, TEST_VARIABLE_KEY);
    assert_int_equal(rval, DAQ_ERROR);
}

int main(void)
{
    int rval;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_no_config),
        cmocka_unit_test(test_no_module_config),
        cmocka_unit_test_setup_teardown(test_input, daq_config_bringup, daq_config_teardown),
        cmocka_unit_test_setup_teardown(test_snaplen, daq_config_bringup, daq_config_teardown),
        cmocka_unit_test_setup_teardown(test_timeout, daq_config_bringup, daq_config_teardown),
        cmocka_unit_test_setup_teardown(test_module_mode, daq_config_bringup, daq_config_teardown),
        cmocka_unit_test_setup_teardown(test_module_variables, daq_config_bringup, daq_config_teardown),
    };

    rval = daq_load_static_modules(static_modules);
    assert_int_equal(rval, 1);

    return cmocka_run_group_tests(tests, NULL, NULL);
}

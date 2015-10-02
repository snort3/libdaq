#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include "daq.h"

static void test_no_config(void **state)
{
    int rval;

    rval = daq_config_push_module_config(NULL, NULL);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_null(daq_config_pop_module_config(NULL));
    
    assert_null(daq_config_top_module_config(NULL));

    assert_null(daq_config_next_module_config(NULL));
}

static void test_no_module_config(void **state)
{
    const char *key, *value;
    int rval;

    assert_null(daq_module_config_get_module(NULL));

    rval = daq_module_config_set_input(NULL, "input");
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_null(daq_module_config_get_input(NULL));

    rval = daq_module_config_set_snaplen(NULL, 1518);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_int_equal(daq_module_config_get_snaplen(NULL), 0);

    rval = daq_module_config_set_timeout(NULL, 1000);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_int_equal(daq_module_config_get_timeout(NULL), 0);

    rval = daq_module_config_set_mode(NULL, DAQ_MODE_PASSIVE);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_int_equal(daq_module_config_get_mode(NULL), DAQ_MODE_NONE);

    rval = daq_module_config_set_variable(NULL, "key", "value");
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_null(daq_module_config_get_variable(NULL, "key"));

    rval = daq_module_config_delete_variable(NULL, "key");
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    rval = daq_module_config_first_variable(NULL, &key, &value);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    rval = daq_module_config_next_variable(NULL, &key, &value);
    assert_int_equal(rval, DAQ_ERROR_INVAL);

    assert_null(daq_module_config_get_next(NULL));
}

static int create_daq_config(void **state)
{
    DAQ_Config_h config;

    if (daq_config_new(&config) != DAQ_SUCCESS)
        return -1;
    *state = config;
    return 0;
}

static int destroy_daq_config(void **state)
{
    DAQ_Config_h config = (DAQ_Config_h) *state;
    daq_config_destroy(config);
    return 0;
}

static void test_config_no_module(void **state)
{
    DAQ_Config_h config = *state;


}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_no_config),
        cmocka_unit_test(test_no_module_config),
        cmocka_unit_test_setup_teardown(test_config_no_module, create_daq_config, destroy_daq_config),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

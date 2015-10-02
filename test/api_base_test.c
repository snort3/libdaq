#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include "daq.h"
#include "daq_api.h"
#include "mock_stdio.h"

#define TEST_MODULE_VERSION    1

static const DAQ_ModuleAPI_t test_module =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ TEST_MODULE_VERSION,
    /* .name = */ "test",
    /* .type = */ 0,
    /* .prepare = */ NULL,
    /* .get_variable_descs = */ NULL,
    /* .initialize = */ NULL,
    /* .set_filter = */ NULL,
    /* .start = */ NULL,
    /* .inject = */ NULL,
    /* .breakloop = */ NULL,
    /* .stop = */ NULL,
    /* .shutdown = */ NULL,
    /* .check_status = */ NULL,
    /* .get_stats = */ NULL,
    /* .reset_stats = */ NULL,
    /* .get_snaplen = */ NULL,
    /* .get_capabilities = */ NULL,
    /* .get_datalink_type = */ NULL,
    /* .get_errbuf = */ NULL,
    /* .set_errbuf = */ NULL,
    /* .get_device_index = */ NULL,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ NULL,
    /* .msg_finalize = */ NULL,
    /* .packet_header_from_msg = */ NULL,
    /* .packet_data_from_msg = */ NULL,
};

const DAQ_ModuleAPI_t *test_static_modules[] =
{
    &test_module,
};
const int test_num_static_modules = sizeof(test_static_modules) / sizeof(test_static_modules[0]);

DAQ_ModuleAPI_t **static_modules = NULL;
int num_static_modules = 0;

static void test_verbosity(void **state)
{
    daq_set_verbosity(3);
    assert_int_equal(daq_get_verbosity(), 3);
    assert_string_equal(mock_stdio_get_stdout(), "DAQ verbosity level is set to 3.\n");
    daq_set_verbosity(0);
    assert_int_equal(daq_get_verbosity(), 0);
}

#define BAD_MODULE_PATH "deadbeef"
#define BAD_MODULE_PATH_STRING "Unable to open directory \"" BAD_MODULE_PATH "\"\n"
static void test_daq_load_modules(void **state)
{
    int rv;

    const char *bad_directory_list[] = {
        BAD_MODULE_PATH,
        NULL
    };
    rv = daq_load_modules(bad_directory_list);
    assert_int_equal(rv, DAQ_SUCCESS);
    assert_string_equal(mock_stdio_get_stderr(), BAD_MODULE_PATH_STRING);
    daq_unload_modules();
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_verbosity),
        cmocka_unit_test(test_daq_load_modules),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

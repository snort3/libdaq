#include <dirent.h>
#include <dlfcn.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/stat.h>

#include <cmocka.h>

#include "daq.h"
#include "daq_api.h"
#include "mock_stdio.h"

#define TEST1_MODULE_NAME       "Test"
#define TEST1_MODULE_VERSION    1
#define TEST2_MODULE_NAME       "Test"
#define TEST2_MODULE_VERSION    3
#define TEST3_MODULE_NAME       "BadAPIVersionTest"
#define TEST3_MODULE_VERSION    1
#define TEST3_MODULE_API_VERSION    (DAQ_MODULE_API_VERSION - 1)
#define TEST4_MODULE_NAME       "BadAPISizeTest"
#define TEST4_MODULE_VERSION    1
#define TEST4_MODULE_API_SIZE   (sizeof(DAQ_ModuleAPI_t) - 1)
#define TEST5_MODULE_NAME       "MissingFunctionsTest"
#define TEST5_MODULE_VERSION    1
#define TEST_MODULE_TYPE        (DAQ_TYPE_FILE_CAPABLE|DAQ_TYPE_INTF_CAPABLE|DAQ_TYPE_INLINE_CAPABLE|DAQ_TYPE_MULTI_INSTANCE|DAQ_TYPE_NO_UNPRIV|DAQ_TYPE_WRAPPER)

static int daq_test_prepare(const DAQ_BaseAPI_t *base_api)
{
    return DAQ_SUCCESS;
}

static int daq_test_initialize(const DAQ_ModuleConfig_h config, void **ctxt_ptr, char *errbuf, size_t len)
{
    return DAQ_SUCCESS;
}

static int daq_test_start(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    return DAQ_SUCCESS;
}

static int daq_test_breakloop(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_stop(void *handle)
{
    return DAQ_SUCCESS;
}

void daq_test_shutdown(void *handle)
{
}

DAQ_State daq_test_check_status(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_stats(void *handle, DAQ_Stats_t *stats)
{
    return DAQ_SUCCESS;
}

void daq_test_reset_stats(void *handle)
{
}

static int daq_test_get_snaplen(void *handle)
{
    return DAQ_SUCCESS;
}

uint32_t daq_test_get_capabilities(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_datalink_type(void *handle)
{
    return DAQ_SUCCESS;
}

const char *daq_test_get_errbuf(void *handle)
{
    return DAQ_SUCCESS;
}

void daq_test_set_errbuf(void *handle, const char *string)
{
}

static int daq_test_get_device_index(void *handle, const char *device)
{
    return DAQ_SUCCESS;
}

static int daq_test_msg_receive(void *handle, const DAQ_Msg_t **msgptr)
{
    return DAQ_SUCCESS;
}

static int daq_test_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    return DAQ_SUCCESS;
}

DAQ_PktHdr_t *daq_test_packet_header_from_msg(void *handle, const DAQ_Msg_t *msg)
{
    return NULL;
}

const uint8_t *daq_test_packet_data_from_msg(void *handle, const DAQ_Msg_t *msg)
{
    return NULL;
}


static DAQ_ModuleAPI_t test1_module =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ TEST1_MODULE_VERSION,
    /* .name = */ TEST1_MODULE_NAME,
    /* .type = */ TEST_MODULE_TYPE,
    /* .prepare = */ daq_test_prepare,
    /* .get_variable_descs = */ NULL,
    /* .initialize = */ daq_test_initialize,
    /* .set_filter = */ NULL,
    /* .start = */ daq_test_start,
    /* .inject = */ daq_test_inject,
    /* .breakloop = */ daq_test_breakloop,
    /* .stop = */ daq_test_stop,
    /* .shutdown = */ daq_test_shutdown,
    /* .check_status = */ daq_test_check_status,
    /* .get_stats = */ daq_test_get_stats,
    /* .reset_stats = */ daq_test_reset_stats,
    /* .get_snaplen = */ daq_test_get_snaplen,
    /* .get_capabilities = */ daq_test_get_capabilities,
    /* .get_datalink_type = */ daq_test_get_datalink_type,
    /* .get_errbuf = */ daq_test_get_errbuf,
    /* .set_errbuf = */ daq_test_set_errbuf,
    /* .get_device_index = */ daq_test_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ daq_test_msg_receive,
    /* .msg_finalize = */ daq_test_msg_finalize,
    /* .packet_header_from_msg = */ daq_test_packet_header_from_msg,
    /* .packet_data_from_msg = */ daq_test_packet_data_from_msg,
};

static DAQ_ModuleAPI_t test2_module =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ TEST2_MODULE_VERSION,
    /* .name = */ TEST2_MODULE_NAME,
    /* .type = */ TEST_MODULE_TYPE,
    /* .prepare = */ daq_test_prepare,
    /* .get_variable_descs = */ NULL,
    /* .initialize = */ daq_test_initialize,
    /* .set_filter = */ NULL,
    /* .start = */ daq_test_start,
    /* .inject = */ daq_test_inject,
    /* .breakloop = */ daq_test_breakloop,
    /* .stop = */ daq_test_stop,
    /* .shutdown = */ daq_test_shutdown,
    /* .check_status = */ daq_test_check_status,
    /* .get_stats = */ daq_test_get_stats,
    /* .reset_stats = */ daq_test_reset_stats,
    /* .get_snaplen = */ daq_test_get_snaplen,
    /* .get_capabilities = */ daq_test_get_capabilities,
    /* .get_datalink_type = */ daq_test_get_datalink_type,
    /* .get_errbuf = */ daq_test_get_errbuf,
    /* .set_errbuf = */ daq_test_set_errbuf,
    /* .get_device_index = */ daq_test_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ daq_test_msg_receive,
    /* .msg_finalize = */ daq_test_msg_finalize,
    /* .packet_header_from_msg = */ daq_test_packet_header_from_msg,
    /* .packet_data_from_msg = */ daq_test_packet_data_from_msg,
};

static DAQ_ModuleAPI_t test3_module =
{
    /* .api_version = */ TEST3_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ TEST3_MODULE_VERSION,
    /* .name = */ TEST3_MODULE_NAME,
    /* .type = */ TEST_MODULE_TYPE,
    /* .prepare = */ daq_test_prepare,
    /* .get_variable_descs = */ NULL,
    /* .initialize = */ daq_test_initialize,
    /* .set_filter = */ NULL,
    /* .start = */ daq_test_start,
    /* .inject = */ daq_test_inject,
    /* .breakloop = */ daq_test_breakloop,
    /* .stop = */ daq_test_stop,
    /* .shutdown = */ daq_test_shutdown,
    /* .check_status = */ daq_test_check_status,
    /* .get_stats = */ daq_test_get_stats,
    /* .reset_stats = */ daq_test_reset_stats,
    /* .get_snaplen = */ daq_test_get_snaplen,
    /* .get_capabilities = */ daq_test_get_capabilities,
    /* .get_datalink_type = */ daq_test_get_datalink_type,
    /* .get_errbuf = */ daq_test_get_errbuf,
    /* .set_errbuf = */ daq_test_set_errbuf,
    /* .get_device_index = */ daq_test_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ daq_test_msg_receive,
    /* .msg_finalize = */ daq_test_msg_finalize,
    /* .packet_header_from_msg = */ daq_test_packet_header_from_msg,
    /* .packet_data_from_msg = */ daq_test_packet_data_from_msg,
};

static DAQ_ModuleAPI_t test4_module =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ TEST4_MODULE_API_SIZE,
    /* .module_version = */ TEST4_MODULE_VERSION,
    /* .name = */ TEST4_MODULE_NAME,
    /* .type = */ TEST_MODULE_TYPE,
    /* .prepare = */ daq_test_prepare,
    /* .get_variable_descs = */ NULL,
    /* .initialize = */ daq_test_initialize,
    /* .set_filter = */ NULL,
    /* .start = */ daq_test_start,
    /* .inject = */ daq_test_inject,
    /* .breakloop = */ daq_test_breakloop,
    /* .stop = */ daq_test_stop,
    /* .shutdown = */ daq_test_shutdown,
    /* .check_status = */ daq_test_check_status,
    /* .get_stats = */ daq_test_get_stats,
    /* .reset_stats = */ daq_test_reset_stats,
    /* .get_snaplen = */ daq_test_get_snaplen,
    /* .get_capabilities = */ daq_test_get_capabilities,
    /* .get_datalink_type = */ daq_test_get_datalink_type,
    /* .get_errbuf = */ daq_test_get_errbuf,
    /* .set_errbuf = */ daq_test_set_errbuf,
    /* .get_device_index = */ daq_test_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ daq_test_msg_receive,
    /* .msg_finalize = */ daq_test_msg_finalize,
    /* .packet_header_from_msg = */ daq_test_packet_header_from_msg,
    /* .packet_data_from_msg = */ daq_test_packet_data_from_msg,
};

static DAQ_ModuleAPI_t test5_module =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ TEST5_MODULE_VERSION,
    /* .name = */ TEST5_MODULE_NAME,
    /* .type = */ TEST_MODULE_TYPE,
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


static const DAQ_ModuleAPI_t *static_modules[] =
{
    &test1_module,
    &test2_module,
    &test3_module,
    &test4_module,
    &test5_module,
    NULL
};
static const int num_static_modules = sizeof(static_modules) / sizeof(static_modules[0]) - 1;

static void test_verbosity(void **state)
{
    mock_stdio_set_capture_stdout(true);
    daq_set_verbosity(3);
    assert_int_equal(daq_get_verbosity(), 3);
    assert_string_equal(mock_stdio_get_stdout(), "DAQ verbosity level is set to 3.\n");
    mock_stdio_set_capture_stdout(false);

    daq_set_verbosity(0);
    assert_int_equal(daq_get_verbosity(), 0);
}

/* OK, this one is pretty dumb... */
static struct mode_xlate {
    DAQ_Mode mode;
    const char *str;
} mode_translations[MAX_DAQ_MODE] =
{
    { DAQ_MODE_NONE, "none" },
    { DAQ_MODE_PASSIVE, "passive" },
    { DAQ_MODE_INLINE, "inline" },
    { DAQ_MODE_READ_FILE, "read-file" }
};

static struct state_xlate {
    DAQ_State state;
    const char *str;
} state_translations[MAX_DAQ_STATE] =
{
    { DAQ_STATE_UNINITIALIZED, "uninitialized" },
    { DAQ_STATE_INITIALIZED, "initialized" },
    { DAQ_STATE_STARTED, "started" },
    { DAQ_STATE_STOPPED, "stopped" },
    { DAQ_STATE_UNKNOWN, "unknown" },
};

static struct verdict_xlate {
    DAQ_Verdict verdict;
    const char *str;
} verdict_translations[MAX_DAQ_VERDICT] =
{
    { DAQ_VERDICT_PASS, "pass" },
    { DAQ_VERDICT_BLOCK, "block" },
    { DAQ_VERDICT_REPLACE, "replace" },
    { DAQ_VERDICT_WHITELIST, "whitelist" },
    { DAQ_VERDICT_BLACKLIST, "blacklist" },
    { DAQ_VERDICT_IGNORE, "ignore" },
    { DAQ_VERDICT_RETRY, "retry" },
};

static void test_string_translation(void **state)
{
    int i;

    for (i = 0; i < MAX_DAQ_MODE; i++)
        assert_string_equal(daq_mode_string(mode_translations[i].mode), mode_translations[i].str);
    assert_null(daq_mode_string(MAX_DAQ_MODE));
    for (i = 0; i < MAX_DAQ_STATE; i++)
        assert_string_equal(daq_state_string(state_translations[i].state), state_translations[i].str);
    assert_null(daq_state_string(MAX_DAQ_STATE));
    for (i = 0; i < MAX_DAQ_VERDICT; i++)
        assert_string_equal(daq_verdict_string(verdict_translations[i].verdict), verdict_translations[i].str);
    assert_null(daq_verdict_string(MAX_DAQ_VERDICT));
}

DIR *__wrap_opendir(const char *name)
{
    check_expected_ptr(name);
    return (DIR *) mock();
}

struct dirent *__wrap_readdir(DIR *dirp)
{
    check_expected_ptr(dirp);
    return (struct dirent *) mock();
}

int __wrap_closedir(DIR *dirp)
{
    check_expected_ptr(dirp);
    return 0;
}

int __wrap_stat(const char *pathname, struct stat *buf)
{
    check_expected_ptr(pathname);
    buf->st_mode = S_IFREG;
    return mock();
}

void *__wrap_dlopen(const char *filename, int flags)
{
    check_expected_ptr(filename);
    check_expected(flags);

    return (void *) mock();
}

void *__wrap_dlsym(void *handle, const char *symbol)
{
    check_expected_ptr(handle);
    check_expected_ptr(symbol);

    return (void *) mock();
}

int __wrap_dlclose(void *handle)
{
    check_expected_ptr(handle);
    return 0;
}

#define MODULE_PATH "."
#define BAD_MODULE_NAME "deadbeef"
#define BAD_MODULE_PATH_STRING "Unable to open directory \"" MODULE_PATH "\"\n"
static struct dirent null_dir_entry;
static struct dirent deadbeef_dir_entry = 
{
    .d_name = BAD_MODULE_NAME ".so"
};
static void test_daq_load_modules(void **state)
{
    DAQ_Module_h module;
    int rval;

    const char *bad_directory_list[] = {
        MODULE_PATH,
        "",
        NULL
    };
    mock_stdio_set_capture_stderr(true);
    expect_string(__wrap_opendir, name, MODULE_PATH);
    will_return(__wrap_opendir, NULL);
    rval = daq_load_dynamic_modules(bad_directory_list);
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_string_equal(mock_stdio_get_stderr(), BAD_MODULE_PATH_STRING);
    mock_stdio_set_capture_stderr(false);

    rval = daq_load_static_modules(static_modules);
    assert_int_equal(rval, num_static_modules);
    module = daq_modules_first();
    assert_non_null(module);
    assert_string_equal(daq_module_get_name(module), TEST1_MODULE_NAME);
    assert_int_equal(daq_module_get_version(module), TEST2_MODULE_VERSION);
    assert_int_equal(daq_module_get_type(module), TEST_MODULE_TYPE);
    module = daq_modules_next();
    assert_null(module);

    module = daq_find_module(TEST1_MODULE_NAME);
    assert_non_null(module);
    module = daq_find_module(NULL);
    assert_null(module);
    module = daq_find_module(BAD_MODULE_NAME);
    assert_null(module);

    daq_unload_modules();
    module = daq_modules_first();
    assert_null(module);


    expect_string(__wrap_opendir, name, MODULE_PATH);
    will_return(__wrap_opendir, 0xdeadbeef);

    expect_value(__wrap_readdir, dirp, 0xdeadbeef);
    will_return(__wrap_readdir, &deadbeef_dir_entry);
    expect_string(__wrap_stat, pathname, MODULE_PATH "/" BAD_MODULE_NAME ".so");
    will_return(__wrap_stat, 0);
    expect_string(__wrap_dlopen, filename, MODULE_PATH "/" BAD_MODULE_NAME ".so");
    expect_value(__wrap_dlopen, flags, RTLD_NOW);
    will_return(__wrap_dlopen, 0xdeadbeef);
    expect_value(__wrap_dlsym, handle, 0xdeadbeef);
    expect_string(__wrap_dlsym, symbol, "DAQ_MODULE_DATA");
    will_return(__wrap_dlsym, &test1_module);
    expect_value(__wrap_dlclose, handle, 0xdeadbeef);

    expect_value(__wrap_readdir, dirp, 0xdeadbeef);
    will_return(__wrap_readdir, &null_dir_entry);
    expect_value(__wrap_readdir, dirp, 0xdeadbeef);
    will_return(__wrap_readdir, NULL);
    expect_value(__wrap_closedir, dirp, 0xdeadbeef);
    rval = daq_load_dynamic_modules(bad_directory_list);
    assert_int_equal(rval, DAQ_SUCCESS);

    module = daq_modules_first();
    assert_non_null(module);
    assert_string_equal(daq_module_get_name(module), TEST1_MODULE_NAME);
    assert_int_equal(daq_module_get_version(module), TEST1_MODULE_VERSION);
    assert_int_equal(daq_module_get_type(module), TEST_MODULE_TYPE);
    module = daq_modules_next();
    assert_null(module);

    module = daq_find_module(TEST1_MODULE_NAME);
    assert_non_null(module);

    daq_unload_modules();
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_verbosity),
        cmocka_unit_test(test_string_translation),
        cmocka_unit_test(test_daq_load_modules),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

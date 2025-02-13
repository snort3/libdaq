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

#include <dirent.h>
#include <dlfcn.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>

#include <cmocka.h>

#include "daq.h"
#include "mock_stdio.h"

#include "daq_test_module.h"

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

DIR *__wrap_opendir(const char *name);
DIR *__wrap_opendir(const char *name)
{
    check_expected_ptr(name);
    return (DIR *) mock();
}

struct dirent *__wrap_readdir(DIR *dirp);
struct dirent *__wrap_readdir(DIR *dirp)
{
    check_expected_ptr(dirp);
    return (struct dirent *) mock();
}

int __wrap_closedir(DIR *dirp);
int __wrap_closedir(DIR *dirp)
{
    check_expected_ptr(dirp);
    return 0;
}

#ifdef __USE_EXTERN_INLINES

int __wrap___xstat(int ver, const char *pathname, struct stat *buf);
int __wrap___xstat(int ver, const char *pathname, struct stat *buf)
{
    check_expected_ptr(pathname);
    buf->st_mode = S_IFREG;
    return mock();
}

#else

int __wrap_stat(const char *pathname, struct stat *buf);
int __wrap_stat(const char *pathname, struct stat *buf)
{
    check_expected_ptr(pathname);
    buf->st_mode = S_IFREG;
    return mock();
}

#endif /* __USE_EXTERN_INLINES */

void *__wrap_dlopen(const char *filename, int flags);
void *__wrap_dlopen(const char *filename, int flags)
{
    check_expected_ptr(filename);
    check_expected(flags);

    return (void *) mock();
}

void *__wrap_dlsym(void *handle, const char *symbol);
void *__wrap_dlsym(void *handle, const char *symbol)
{
    check_expected_ptr(handle);
    check_expected_ptr(symbol);

    return (void *) mock();
}

int __wrap_dlclose(void *handle);
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

static void test_non_existent_dynamic_path(void **state)
{
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
}

static void test_daq_load_modules(void **state)
{
    DAQ_Module_h module;
    int rval;

    const char *bad_directory_list[] = {
        MODULE_PATH,
        NULL
    };

    DAQ_ModuleAPI_t test1_module, test2_module, test3_module, test4_module, test5_module;

    const DAQ_ModuleAPI_t *static_modules[] =
    {
        &test1_module,
        &test1_module,
        &test2_module,
        &test3_module,
        &test4_module,
        &test5_module,
        NULL
    };
    const int num_static_modules = sizeof(static_modules) / sizeof(static_modules[0]) - 1;

    memcpy(&test1_module, &test_module, sizeof(DAQ_ModuleAPI_t));
    *(uint32_t *) &test1_module.module_version = TEST1_MODULE_VERSION;
    test1_module.name = TEST1_MODULE_NAME;

    memcpy(&test2_module, &test_module, sizeof(DAQ_ModuleAPI_t));
    *(uint32_t *) &test2_module.module_version = TEST2_MODULE_VERSION;
    test2_module.name = TEST2_MODULE_NAME;

    memcpy(&test3_module, &test_module, sizeof(DAQ_ModuleAPI_t));
    *(uint32_t *) &test3_module.api_version = TEST3_MODULE_API_VERSION;
    *(uint32_t *) &test3_module.module_version = TEST3_MODULE_VERSION;
    test3_module.name = TEST3_MODULE_NAME;

    memcpy(&test4_module, &test_module, sizeof(DAQ_ModuleAPI_t));
    *(uint32_t *) &test4_module.api_size = TEST4_MODULE_API_SIZE;
    *(uint32_t *) &test4_module.module_version = TEST4_MODULE_VERSION;
    test4_module.name = TEST4_MODULE_NAME;

    memset(&test5_module, 0, sizeof(DAQ_ModuleAPI_t));
    *(uint32_t *) &test5_module.api_version = DAQ_MODULE_API_VERSION;
    *(uint32_t *) &test5_module.api_size = sizeof(DAQ_ModuleAPI_t);
    *(uint32_t *) &test5_module.module_version = TEST5_MODULE_VERSION;
    test5_module.name = TEST5_MODULE_NAME;
    *(uint32_t *) &test5_module.type = TEST_MODULE_TYPE;

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
#ifdef __USE_EXTERN_INLINES
    expect_string(__wrap___xstat, pathname, MODULE_PATH "/" BAD_MODULE_NAME ".so");
    will_return(__wrap___xstat, 0);
#else
    expect_string(__wrap_stat, pathname, MODULE_PATH "/" BAD_MODULE_NAME ".so");
    will_return(__wrap_stat, 0);
#endif
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
        cmocka_unit_test(test_non_existent_dynamic_path),
        cmocka_unit_test(test_daq_load_modules),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

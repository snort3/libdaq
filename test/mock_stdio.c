#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>

#include <cmocka.h>

#include "mock_stdio.h"

static char stdout_mock_buffer[4096];
static int stdout_mock_buffer_pos = 0;
static char stderr_mock_buffer[4096];
static int stderr_mock_buffer_pos = 0;

int __wrap_printf(const char *format, ...) CMOCKA_PRINTF_ATTRIBUTE(1, 2);
int __wrap___printf_chk(int flag, const char *format, ...) CMOCKA_PRINTF_ATTRIBUTE(2, 3);
int __wrap_fprintf(FILE* const file, const char *format, ...) CMOCKA_PRINTF_ATTRIBUTE(2, 3);
int __wrap___fprintf_chk(FILE* const file, int flag, const char *format, ...) CMOCKA_PRINTF_ATTRIBUTE(3, 4);

const char *mock_stdio_get_stdout(void)
{
    return stdout_mock_buffer;
}

void mock_stdio_reset_stdout(void)
{
    stdout_mock_buffer[0] = '\0';
    stdout_mock_buffer_pos = 0;
}

const char *mock_stdio_get_stderr(void)
{
    return stderr_mock_buffer;
}

void mock_stdio_reset_stderr(void)
{
    stderr_mock_buffer[0] = '\0';
    stderr_mock_buffer_pos = 0;
}

/* A mock printf function that captures standard output. */
int __wrap_printf(const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = vsnprintf(stdout_mock_buffer + stdout_mock_buffer_pos, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos, format, args);
    if (ret >= (int) sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos)
        stdout_mock_buffer_pos = sizeof(stdout_mock_buffer);
    else if (ret > 0)
        stdout_mock_buffer_pos += ret;
    va_end(args);
    return ret;
}

/* A mock checked printf function that captures standard output. */
int __wrap___printf_chk(int flag, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = __vsnprintf_chk(stdout_mock_buffer + stdout_mock_buffer_pos, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos,
            flag, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos, format, args);
    if (ret >= (int) sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos)
        stdout_mock_buffer_pos = sizeof(stdout_mock_buffer);
    else if (ret > 0)
        stdout_mock_buffer_pos += ret;
    va_end(args);
    return ret;
}


/* A mock fprintf function that captures standard error and standard output. */
int __wrap_fprintf(FILE* const file, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    if (file == stdout)
    {
        ret = vsnprintf(stdout_mock_buffer + stdout_mock_buffer_pos, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos)
            stdout_mock_buffer_pos = sizeof(stdout_mock_buffer);
        else if (ret > 0)
            stdout_mock_buffer_pos += ret;
/*
        __real_fprintf(stdout, "%s: Update stdout buffer (ret = %d, pos = %d): '%s'\n",
                __FUNCTION__, ret, stdout_mock_buffer_pos, stdout_mock_buffer);
*/
    }
    else if (file == stderr)
    {
        ret = vsnprintf(stderr_mock_buffer + stderr_mock_buffer_pos, sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos)
            stderr_mock_buffer_pos = sizeof(stderr_mock_buffer);
        else if (ret > 0)
            stderr_mock_buffer_pos += ret;
/*
        __real_fprintf(stdout, "%s: Update stderr buffer (ret = %d, pos = %d): '%s'\n",
                __FUNCTION__, ret, stderr_mock_buffer_pos, stderr_mock_buffer);
*/
    }
    else
        ret = vfprintf(file, format, args);
    va_end(args);
    return ret;
}

/* A mock checked fprintf function that captures standard error and standard output. */
int __wrap___fprintf_chk(FILE* const file, int flag, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    if (file == stdout)
    {
        ret = __vsnprintf_chk(stdout_mock_buffer + stdout_mock_buffer_pos, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos,
                flag, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos)
            stdout_mock_buffer_pos = sizeof(stdout_mock_buffer);
        else if (ret > 0)
            stdout_mock_buffer_pos += ret;
/*
        __real_fprintf(stdout, "%s: Update stdout buffer (ret = %d, pos = %d): '%s'\n",
                __FUNCTION__, ret, stdout_mock_buffer_pos, stdout_mock_buffer);
*/
    }
    else if (file == stderr)
    {
        ret = __vsnprintf_chk(stderr_mock_buffer + stderr_mock_buffer_pos, sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos,
                flag, sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos)
            stderr_mock_buffer_pos = sizeof(stderr_mock_buffer);
        else if (ret > 0)
            stderr_mock_buffer_pos += ret;
/*
        __real_fprintf(stdout, "%s: Update stderr buffer (ret = %d, pos = %d): '%s'\n",
                __FUNCTION__, ret, stderr_mock_buffer_pos, stderr_mock_buffer);
*/
    }
    else
        ret = __vfprintf_chk(file, flag, format, args);
    va_end(args);
    return ret;
}


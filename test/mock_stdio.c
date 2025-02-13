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
#include <stdio.h>

#include <cmocka.h>

#include "mock_stdio.h"

static char stdout_mock_buffer[4096];
static int stdout_mock_buffer_pos = 0;
static bool capture_stdout = false;
static char stderr_mock_buffer[4096];
static int stderr_mock_buffer_pos = 0;
static bool capture_stderr = false;

static bool debug_capture;

int __wrap_printf(const char *format, ...) CMOCKA_PRINTF_ATTRIBUTE(1, 2);
int __wrap___printf_chk(int flag, const char *format, ...) CMOCKA_PRINTF_ATTRIBUTE(2, 3);
int __wrap_fprintf(FILE* const file, const char *format, ...) CMOCKA_PRINTF_ATTRIBUTE(2, 3);
int __wrap___fprintf_chk(FILE* const file, int flag, const char *format, ...) CMOCKA_PRINTF_ATTRIBUTE(3, 4);

/* Function declaration to make the compiler happy. */
int __real_printf(const char *fmt, ...) __attribute__ ((weak)) CMOCKA_PRINTF_ATTRIBUTE(1, 2);

void mock_stdio_set_debug_capture(bool debug)
{
    debug_capture = debug;
}

const char *mock_stdio_get_stdout(void)
{
    return stdout_mock_buffer;
}

void mock_stdio_reset_stdout(void)
{
    stdout_mock_buffer[0] = '\0';
    stdout_mock_buffer_pos = 0;
}

void mock_stdio_set_capture_stdout(bool capture)
{
    mock_stdio_reset_stdout();
    capture_stdout = capture;
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

void mock_stdio_set_capture_stderr(bool capture)
{
    mock_stdio_reset_stderr();
    capture_stderr = capture;
}

/* A mock printf function that captures standard output. */
int __wrap_printf(const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    if (capture_stdout)
    {
        ret = vsnprintf(stdout_mock_buffer + stdout_mock_buffer_pos, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos)
            stdout_mock_buffer_pos = sizeof(stdout_mock_buffer);
        else if (ret > 0)
            stdout_mock_buffer_pos += ret;
        if (debug_capture)
        {
            __real_printf("%s: Update stdout buffer (ret = %d, pos = %d): '%s'\n",
                    __func__, ret, stdout_mock_buffer_pos, stdout_mock_buffer);
        }
    }
    else
        ret = vprintf(format, args);
    va_end(args);
    return ret;
}

/* A mock checked printf function that captures standard output. */
int __wrap___printf_chk(int flag, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    if (capture_stdout)
    {
        ret = __vsnprintf_chk(stdout_mock_buffer + stdout_mock_buffer_pos, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos,
                flag, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos)
            stdout_mock_buffer_pos = sizeof(stdout_mock_buffer);
        else if (ret > 0)
            stdout_mock_buffer_pos += ret;
        if (debug_capture)
        {
            __real_printf("%s: Update stdout buffer (ret = %d, pos = %d): '%s'\n",
                    __func__, ret, stdout_mock_buffer_pos, stdout_mock_buffer);
        }
    }
    else
        ret = __vprintf_chk(flag, format, args);
    va_end(args);
    return ret;
}


/* A mock fprintf function that captures standard error and standard output. */
int __wrap_fprintf(FILE* const file, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    if (file == stdout && capture_stdout)
    {
        ret = vsnprintf(stdout_mock_buffer + stdout_mock_buffer_pos, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos)
            stdout_mock_buffer_pos = sizeof(stdout_mock_buffer);
        else if (ret > 0)
            stdout_mock_buffer_pos += ret;
        if (debug_capture)
        {
            __real_printf("%s: Update stdout buffer (ret = %d, pos = %d): '%s'\n",
                    __func__, ret, stdout_mock_buffer_pos, stdout_mock_buffer);
        }
    }
    else if (file == stderr && capture_stderr)
    {
        ret = vsnprintf(stderr_mock_buffer + stderr_mock_buffer_pos, sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos)
            stderr_mock_buffer_pos = sizeof(stderr_mock_buffer);
        else if (ret > 0)
            stderr_mock_buffer_pos += ret;
        if (debug_capture)
        {
            __real_printf("%s: Update stderr buffer (ret = %d, pos = %d): '%s'\n",
                    __func__, ret, stderr_mock_buffer_pos, stderr_mock_buffer);
        }
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
    if (file == stdout && capture_stdout)
    {
        ret = __vsnprintf_chk(stdout_mock_buffer + stdout_mock_buffer_pos, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos,
                flag, sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stdout_mock_buffer) - stdout_mock_buffer_pos)
            stdout_mock_buffer_pos = sizeof(stdout_mock_buffer);
        else if (ret > 0)
            stdout_mock_buffer_pos += ret;
        if (debug_capture)
        {
            __real_printf("%s: Update stdout buffer (ret = %d, pos = %d): '%s'\n",
                    __func__, ret, stdout_mock_buffer_pos, stdout_mock_buffer);
        }
    }
    else if (file == stderr && capture_stderr)
    {
        ret = __vsnprintf_chk(stderr_mock_buffer + stderr_mock_buffer_pos, sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos,
                flag, sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos, format, args);
        if (ret >= (int) sizeof(stderr_mock_buffer) - stderr_mock_buffer_pos)
            stderr_mock_buffer_pos = sizeof(stderr_mock_buffer);
        else if (ret > 0)
            stderr_mock_buffer_pos += ret;
        if (debug_capture)
        {
            __real_printf("%s: Update stderr buffer (ret = %d, pos = %d): '%s'\n",
                    __func__, ret, stderr_mock_buffer_pos, stderr_mock_buffer);
        }
    }
    else
        ret = __vfprintf_chk(file, flag, format, args);
    va_end(args);
    return ret;
}


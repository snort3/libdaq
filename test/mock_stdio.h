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

#ifndef _MOCK_STDIO_H
#define _MOCK_STDIO_H

#include <stdbool.h>

void mock_stdio_set_debug_capture(bool debug);
const char *mock_stdio_get_stdout(void);
void mock_stdio_reset_stdout(void);
void mock_stdio_set_capture_stdout(bool capture);
const char *mock_stdio_get_stderr(void);
void mock_stdio_reset_stderr(void);
void mock_stdio_set_capture_stderr(bool capture);

#endif

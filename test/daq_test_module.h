/*
** Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifndef _DAQ_TEST_MODULE_H
#define _DAQ_TEST_MODULE_H

#include <daq_module_api.h>

#define TEST_MODULE_VERSION 1
#define TEST_MODULE_NAME    "Test"
#define TEST_MODULE_TYPE    (DAQ_TYPE_INTF_CAPABLE|DAQ_TYPE_INLINE_CAPABLE|DAQ_TYPE_MULTI_INSTANCE|DAQ_TYPE_NO_UNPRIV)

extern DAQ_ModuleAPI_t test_module;

#endif

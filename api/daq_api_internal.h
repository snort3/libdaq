/*
** Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifndef _DAQ_API_INTERNAL_H
#define _DAQ_API_INTERNAL_H

#include <stdarg.h>
#include <stdio.h>

#include "daq_module_api.h"

extern int daq_verbosity;

#define DEBUG(...) do { if (daq_verbosity > 0) { printf(__VA_ARGS__); } } while (0)

DAQ_Config_h daq_module_config_get_config(DAQ_ModuleConfig_h modcfg);
DAQ_Instance_h daq_modinst_get_instance(DAQ_ModuleInstance_h modinst);
int daq_modinst_resolve_subapi(DAQ_ModuleInstance_h modinst, DAQ_InstanceAPI_t *api);
void daq_instance_set_errbuf(DAQ_Instance_h instance, const char *format, ...) __attribute__((format (printf, 2, 3)));
void daq_instance_set_errbuf_va(DAQ_Instance_h instance, const char *format, va_list ap);
void populate_base_api(DAQ_BaseAPI_t *base_api);

#endif /* _DAQ_API_INTERNAL_H */

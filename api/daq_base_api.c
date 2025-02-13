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

#include <stdarg.h>

#include "daq.h"
#include "daq_api_internal.h"

static const char *base_api_config_get_input(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_input(cfg);
}

static uint32_t base_api_config_get_msg_pool_size(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_msg_pool_size(cfg);
}

static int base_api_config_get_snaplen(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_snaplen(cfg);
}

static unsigned base_api_config_get_timeout(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_timeout(cfg);
}

static unsigned base_api_config_get_total_instances(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_total_instances(cfg);
}

static unsigned base_api_config_get_instance_id(DAQ_ModuleConfig_h modcfg)
{
    DAQ_Config_h cfg = daq_module_config_get_config(modcfg);
    return daq_config_get_instance_id(cfg);
}

static void base_api_set_errbuf(DAQ_ModuleInstance_h modinst, const char *format, ...)
{
    DAQ_Instance_h instance = daq_modinst_get_instance(modinst);
    va_list ap;
    va_start(ap, format);
    daq_instance_set_errbuf_va(instance, format, ap);
    va_end(ap);
}

void populate_base_api(DAQ_BaseAPI_t *base_api)
{
    base_api->api_version = DAQ_BASE_API_VERSION;
    base_api->api_size = sizeof(DAQ_BaseAPI_t);
    base_api->config_get_input = base_api_config_get_input;
    base_api->config_get_snaplen = base_api_config_get_snaplen;
    base_api->config_get_timeout = base_api_config_get_timeout;
    base_api->config_get_msg_pool_size = base_api_config_get_msg_pool_size;
    base_api->config_get_total_instances = base_api_config_get_total_instances;
    base_api->config_get_instance_id = base_api_config_get_instance_id;
    base_api->config_get_mode = daq_module_config_get_mode;
    base_api->config_get_variable = daq_module_config_get_variable;
    base_api->config_first_variable = daq_module_config_first_variable;
    base_api->config_next_variable = daq_module_config_next_variable;
    base_api->resolve_subapi = daq_modinst_resolve_subapi;
    base_api->set_errbuf = base_api_set_errbuf;
}

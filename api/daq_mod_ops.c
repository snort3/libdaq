/* Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2010-2013 Sourcefire, Inc.
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

#include <stdio.h>
#include <stdlib.h>

#include "daq.h"
#include "daq_api.h"

typedef struct _daq_instance
{
    const DAQ_ModuleAPI_t *module;
    void *context;
} DAQ_Instance_t;

/*
 * Functions that apply to instances of DAQ modules go here.
 */
DAQ_LINKAGE int daq_instance_initialize(const DAQ_Config_h config, const DAQ_Instance_t **instance_ptr, char *errbuf, size_t len)
{
    DAQ_ModuleConfig_h modcfg;
    DAQ_Instance_t *instance;
    int rval;

    /* Don't do this. */
    if (!errbuf)
        return DAQ_ERROR;

    if (!config)
    {
        snprintf(errbuf, len, "Can't initialize without a configuration!");
        return DAQ_ERROR_INVAL;
    }

    if (!instance_ptr)
    {
        snprintf(errbuf, len, "Can't initialize without a context pointer!");
        return DAQ_ERROR_INVAL;
    }

    modcfg = daq_config_top_module_config(config);
    if (!modcfg)
    {
        snprintf(errbuf, len, "Can't initialize without a module configuration!");
        return DAQ_ERROR_INVAL;
    }

    instance = calloc(1, sizeof(const DAQ_Instance_t));
    if (!instance)
    {
        snprintf(errbuf, len, "Couldn't allocate a new DAQ instance structure!");
        return DAQ_ERROR_NOMEM;
    }
    instance->module = daq_module_config_get_module(modcfg);

    rval = instance->module->initialize(modcfg, &instance->context, errbuf, len);
    if (rval != DAQ_SUCCESS)
    {
        free(instance);
        return rval;
    }

    *instance_ptr = instance;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int daq_instance_set_filter(const DAQ_Instance_t *instance, const char *filter)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!instance->module->set_filter)
        return DAQ_ERROR_NOTSUP;

    if (!filter)
    {
        instance->module->set_errbuf(instance->context, "No filter string specified!");
        return DAQ_ERROR_INVAL;
    }

    return instance->module->set_filter(instance->context, filter);
}

DAQ_LINKAGE int daq_instance_start(const DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (instance->module->check_status(instance->context) != DAQ_STATE_INITIALIZED)
    {
        instance->module->set_errbuf(instance->context, "Can't start an instance that isn't initialized!");
        return DAQ_ERROR;
    }

    return instance->module->start(instance->context);
}

DAQ_LINKAGE int daq_instance_inject(const DAQ_Instance_t *instance, const DAQ_PktHdr_t *hdr,
                                        const uint8_t *packet_data, uint32_t len, int reverse)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!hdr)
    {
        instance->module->set_errbuf(instance->context, "No originating packet header specified!");
        return DAQ_ERROR_INVAL;
    }

    if (!packet_data)
    {
        instance->module->set_errbuf(instance->context, "No packet data specified!");
        return DAQ_ERROR_INVAL;
    }

    return instance->module->inject(instance->context, hdr, packet_data, len, reverse);
}

DAQ_LINKAGE int daq_instance_breakloop(const DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->module->breakloop(instance->context);
}

DAQ_LINKAGE int daq_instance_stop(const DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (instance->module->check_status(instance->context) != DAQ_STATE_STARTED)
    {
        instance->module->set_errbuf(instance->context, "Can't stop an instance that hasn't started!");
        return DAQ_ERROR;
    }

    return instance->module->stop(instance->context);
}

DAQ_LINKAGE int daq_instance_shutdown(const DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    instance->module->shutdown(instance->context);
    free((DAQ_Instance_t *) instance);

    return DAQ_SUCCESS;
}

DAQ_LINKAGE DAQ_State daq_instance_check_status(const DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_STATE_UNKNOWN;

    return instance->module->check_status(instance->context);
}

DAQ_LINKAGE int daq_instance_get_stats(const DAQ_Instance_t *instance, DAQ_Stats_t *stats)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!stats)
    {
        instance->module->set_errbuf(instance->context, "No place to put the statistics!");
        return DAQ_ERROR_INVAL;
    }

    return instance->module->get_stats(instance->context, stats);
}

DAQ_LINKAGE void daq_instance_reset_stats(const DAQ_Instance_t *instance)
{
    if (instance)
        instance->module->reset_stats(instance->context);
}

DAQ_LINKAGE int daq_instance_get_snaplen(const DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->module->get_snaplen(instance->context);
}

DAQ_LINKAGE uint32_t daq_instance_get_capabilities(const DAQ_Instance_t *instance)
{
    if (!instance)
        return 0;

    return instance->module->get_capabilities(instance->context);
}

DAQ_LINKAGE int daq_instance_get_datalink_type(const DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->module->get_datalink_type(instance->context);
}

DAQ_LINKAGE const char *daq_instance_get_error(const DAQ_Instance_t *instance)
{
    if (!instance)
        return NULL;

    return instance->module->get_errbuf(instance->context);
}

DAQ_LINKAGE void daq_instance_clear_error(const DAQ_Instance_t *instance)
{
    if (!instance)
        return;

    instance->module->set_errbuf(instance->context, "");
}

DAQ_LINKAGE int daq_instance_get_device_index(const DAQ_Instance_t *instance, const char *device)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!device)
    {
        instance->module->set_errbuf(instance->context, "No device name to find the index of!");
        return DAQ_ERROR_INVAL;
    }

    return instance->module->get_device_index(instance->context, device);
}

DAQ_LINKAGE int daq_instance_hup_prep(const DAQ_Instance_t *instance, void **new_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!instance->module->hup_prep)
    {
        if (!instance->module->hup_apply)
            return 1;
        return DAQ_SUCCESS;
    }

    return instance->module->hup_prep(instance->context, new_config);
}

DAQ_LINKAGE int daq_instance_hup_apply(const DAQ_Instance_t *instance, void *new_config, void **old_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!instance->module->hup_apply)
        return DAQ_SUCCESS;

    return instance->module->hup_apply(instance->context, new_config, old_config);
}

DAQ_LINKAGE int daq_instance_hup_post(const DAQ_Instance_t *instance, void *old_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!instance->module->hup_post)
        return DAQ_SUCCESS;

    return instance->module->hup_post(instance->context, old_config);
}

DAQ_LINKAGE int daq_instance_modify_flow(const DAQ_Instance_t *instance, const DAQ_PktHdr_t *hdr, const DAQ_ModFlow_t *modify)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!instance->module->modify_flow)
        return DAQ_SUCCESS;

    return instance->module->modify_flow(instance->context, hdr, modify);
}

DAQ_LINKAGE int daq_instance_query_flow(const DAQ_Instance_t *instance, const DAQ_PktHdr_t *hdr, DAQ_QueryFlow_t *query)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!instance->module->query_flow)
        return DAQ_ERROR_NOTSUP;

    return instance->module->query_flow(instance->context, hdr, query);
}

DAQ_LINKAGE int daq_instance_dp_add_dc(const DAQ_Instance_t *instance, const DAQ_PktHdr_t *hdr, DAQ_DP_key_t *dp_key,
                                        const uint8_t *packet_data, DAQ_Data_Channel_Params_t *params)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!instance->module->dp_add_dc)
        return DAQ_SUCCESS;

    return instance->module->dp_add_dc(instance->context, hdr, dp_key, packet_data, params);
}

DAQ_LINKAGE unsigned daq_instance_msg_receive(const DAQ_Instance_t *instance, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    if (!instance)
    {
        *rstat = DAQ_RSTAT_INVALID;
        return 0;
    }

    return instance->module->msg_receive(instance->context, max_recv, msgs, rstat);
}

DAQ_LINKAGE int daq_instance_msg_finalize(const DAQ_Instance_t *instance, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->module->msg_finalize(instance->context, msg, verdict);
}

DAQ_LINKAGE DAQ_PktHdr_t *daq_instance_packet_header_from_msg(const DAQ_Instance_t *instance, const DAQ_Msg_t *msg)
{
    if (!instance)
        return NULL;

    return instance->module->packet_header_from_msg(instance->context, msg);
}

DAQ_LINKAGE const uint8_t *daq_instance_packet_data_from_msg(const DAQ_Instance_t *instance, const DAQ_Msg_t *msg)
{
    if (!instance)
        return NULL;

    return instance->module->packet_data_from_msg(instance->context, msg);
}


/*
 * Functions that apply to DAQ modules themselves go here.
 */
DAQ_LINKAGE const char *daq_module_get_name(const DAQ_ModuleAPI_t *module)
{
    if (!module)
        return NULL;

    return module->name;
}

DAQ_LINKAGE uint32_t daq_module_get_version(const DAQ_ModuleAPI_t *module)
{
    if (!module)
        return 0;

    return module->module_version;
}

DAQ_LINKAGE uint32_t daq_module_get_type(const DAQ_ModuleAPI_t *module)
{
    if (!module)
        return DAQ_ERROR_NOMOD;

    return module->type;
}

DAQ_LINKAGE int daq_module_get_variable_descs(const DAQ_ModuleAPI_t *module, const DAQ_VariableDesc_t **var_desc_table)
{
    if (!var_desc_table)
        return 0;

    if (!module || !module->get_variable_descs)
    {
        *var_desc_table = NULL;
        return 0;
    }

    return module->get_variable_descs(var_desc_table);
}

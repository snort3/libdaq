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

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "daq.h"
#include "daq_api.h"
#include "daq_api_internal.h"
#include "daq_instance_api_defaults.h"

/*
 * The DAQ instance contains a top-level API dispatch array that points to the first instance
 * of each module instance API function in the configuration stack along with the associated
 * context or, if none exists, the default implementation for that function.
 * Module instances can generate a similar instance API structure ('subapi') except that it is
 * resolved using only downstream modules in the configuration stack (those being wrapped) and
 * it will not contain default implementations.
 */

typedef struct _daq_module_instance
{
    struct _daq_module_instance *next;
    const DAQ_ModuleAPI_t *module;
    void *context;
} DAQ_ModuleInstance_t;

typedef struct _daq_instance
{
    DAQ_ModuleInstance_t *module_instances;
    DAQ_InstanceAPI_t api;
    char errbuf[DAQ_ERRBUF_SIZE];
} DAQ_Instance_t;


#define CALL_INSTANCE_API(instance, fname, ...) \
    instance->api.fname.func(instance->api.fname.context, __VA_ARGS__)

#define RESOLVE_INSTANCE_API(api, root, fname, dflt)    \
{                                                       \
    for (DAQ_ModuleInstance_t *mi = root;               \
         mi;                                            \
         mi = mi->next)                                 \
    {                                                   \
        if (mi->module->fname)                          \
        {                                               \
            api->fname.func = mi->module->fname ;       \
            api->fname.context = mi->context;           \
            break;                                      \
        }                                               \
    }                                                   \
    if (!api->fname.func && dflt)                       \
        api->fname.func = daq_default_ ## fname;        \
}

static void resolve_instance_api(DAQ_InstanceAPI_t *api, DAQ_ModuleInstance_t *modinst, bool default_impl)
{
    memset(api, 0, sizeof(*api));
    RESOLVE_INSTANCE_API(api, modinst, set_filter, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, start, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, inject, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, breakloop, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, stop, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, shutdown, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, check_status, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_stats, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, reset_stats, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_snaplen, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_capabilities, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_datalink_type, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_device_index, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, modify_flow, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, query_flow, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, hup_prep, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, hup_apply, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, hup_post, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, dp_add_dc, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, msg_receive, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, msg_finalize, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_msg_pool_info, default_impl);
}

static void daq_instance_destroy(DAQ_Instance_t *instance)
{
    if (instance)
    {
        DAQ_ModuleInstance_t *modinst;
        while ((modinst = instance->module_instances) != NULL)
        {
            instance->module_instances = modinst->next;
            free(modinst);
        }
        free(instance);
    }
}


/*
 * Base API functions that apply to an instantiated configuration go here.
 */
void daq_modinst_resolve_subapi(DAQ_ModuleInstance_t *modinst, DAQ_InstanceAPI_t *api)
{
    resolve_instance_api(api, modinst->next, false);
}

void daq_instance_set_errbuf(DAQ_Instance_t *instance, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(instance->errbuf, sizeof(instance->errbuf), format, ap);
    va_end(ap);
}

int daq_module_instantiate(DAQ_ModuleConfig_h modcfg, DAQ_Instance_t *instance)
{
    DAQ_ModuleInstance_t *modinst;

    modinst = calloc(1, sizeof(*modinst));
    if (!modinst)
    {
        daq_instance_set_errbuf(instance, "Couldn't allocate a new DAQ module instance structure!");
        return DAQ_ERROR_NOMEM;
    }

    modinst->module = daq_module_config_get_module(modcfg);

    /* Add this module instance to the bottom of the stack */
    if (instance->module_instances)
    {
        DAQ_ModuleInstance_t *pmi;
        for (pmi = instance->module_instances; pmi->next; pmi = pmi->next);
        pmi->next = modinst;
    }
    else
        instance->module_instances = modinst;

    return modinst->module->initialize(modcfg, instance, modinst, &modinst->context);
}


/*
 * Exported functions that apply to instances of DAQ modules go here.
 */
DAQ_LINKAGE int daq_instance_initialize(const DAQ_Config_h config, DAQ_Instance_t **instance_ptr, char *errbuf, size_t len)
{
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

    DAQ_ModuleConfig_h modcfg = daq_config_top_module_config(config);
    if (!modcfg)
    {
        snprintf(errbuf, len, "Can't initialize without a module configuration!");
        return DAQ_ERROR_INVAL;
    }

    DAQ_Instance_t *instance = calloc(1, sizeof(*instance));
    if (!instance)
    {
        snprintf(errbuf, len, "Couldn't allocate a new DAQ instance structure!");
        return DAQ_ERROR_NOMEM;
    }

    int rval = daq_module_instantiate(modcfg, instance);
    if (rval != DAQ_SUCCESS)
    {
        snprintf(errbuf, len, "%s", instance->errbuf);
        daq_instance_destroy(instance);
        return rval;
    }

    /* Resolve the top-level instance API from the top of the stack with defaults. */
    resolve_instance_api(&instance->api, instance->module_instances, true);

    *instance_ptr = instance;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int daq_instance_set_filter(DAQ_Instance_t *instance, const char *filter)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!filter)
    {
        daq_instance_set_errbuf(instance, "No filter string specified!");
        return DAQ_ERROR_INVAL;
    }

    return instance->api.set_filter.func(instance->api.set_filter.context, filter);
}

DAQ_LINKAGE int daq_instance_start(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (daq_instance_check_status(instance) != DAQ_STATE_INITIALIZED)
    {
        daq_instance_set_errbuf(instance, "Can't start an instance that isn't initialized!");
        return DAQ_ERROR;
    }

    return instance->api.start.func(instance->api.start.context);
}

DAQ_LINKAGE int daq_instance_inject(DAQ_Instance_t *instance, DAQ_Msg_h msg,
                                        const uint8_t *packet_data, uint32_t len, int reverse)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!msg)
    {
        daq_instance_set_errbuf(instance, "No originating packet header specified!");
        return DAQ_ERROR_INVAL;
    }

    if (!packet_data)
    {
        daq_instance_set_errbuf(instance, "No packet data specified!");
        return DAQ_ERROR_INVAL;
    }

    return instance->api.inject.func(instance->api.inject.context, msg, packet_data, len, reverse);
}

DAQ_LINKAGE int daq_instance_breakloop(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.breakloop.func(instance->api.breakloop.context);
}

DAQ_LINKAGE int daq_instance_stop(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (daq_instance_check_status(instance) != DAQ_STATE_STARTED)
    {
        daq_instance_set_errbuf(instance, "Can't stop an instance that hasn't started!");
        return DAQ_ERROR;
    }

    return instance->api.stop.func(instance->api.stop.context);
}

DAQ_LINKAGE int daq_instance_shutdown(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    instance->api.shutdown.func(instance->api.shutdown.context);
    daq_instance_destroy(instance);

    return DAQ_SUCCESS;
}

DAQ_LINKAGE DAQ_State daq_instance_check_status(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_STATE_UNKNOWN;

    return instance->api.check_status.func(instance->api.check_status.context);
}

DAQ_LINKAGE int daq_instance_get_stats(DAQ_Instance_t *instance, DAQ_Stats_t *stats)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!stats)
    {
        daq_instance_set_errbuf(instance, "No place to put the statistics!");
        return DAQ_ERROR_INVAL;
    }

    return instance->api.get_stats.func(instance->api.get_stats.context, stats);
}

DAQ_LINKAGE void daq_instance_reset_stats(DAQ_Instance_t *instance)
{
    if (instance)
        instance->api.reset_stats.func(instance->api.reset_stats.context);
}

DAQ_LINKAGE int daq_instance_get_snaplen(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.get_snaplen.func(instance->api.get_snaplen.context);
}

DAQ_LINKAGE uint32_t daq_instance_get_capabilities(DAQ_Instance_t *instance)
{
    if (!instance)
        return 0;

    return instance->api.get_capabilities.func(instance->api.get_capabilities.context);
}

DAQ_LINKAGE int daq_instance_get_datalink_type(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.get_datalink_type.func(instance->api.get_datalink_type.context);
}

DAQ_LINKAGE const char *daq_instance_get_error(DAQ_Instance_t *instance)
{
    if (!instance)
        return NULL;

    return instance->errbuf;
}

DAQ_LINKAGE int daq_instance_get_device_index(DAQ_Instance_t *instance, const char *device)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!device)
    {
        daq_instance_set_errbuf(instance, "No device name to find the index of!");
        return DAQ_ERROR_INVAL;
    }

    return instance->api.get_device_index.func(instance->api.get_device_index.context, device);
}

DAQ_LINKAGE int daq_instance_hup_prep(DAQ_Instance_t *instance, void **new_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.hup_prep.func(instance->api.hup_prep.context, new_config);
}

DAQ_LINKAGE int daq_instance_hup_apply(DAQ_Instance_t *instance, void *new_config, void **old_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.hup_apply.func(instance->api.hup_apply.context, new_config, old_config);
}

DAQ_LINKAGE int daq_instance_hup_post(DAQ_Instance_t *instance, void *old_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.hup_post.func(instance->api.hup_post.context, old_config);
}

DAQ_LINKAGE int daq_instance_modify_flow(DAQ_Instance_t *instance, DAQ_Msg_h msg, const DAQ_ModFlow_t *modify)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.modify_flow.func(instance->api.modify_flow.context, msg, modify);
}

DAQ_LINKAGE int daq_instance_query_flow(DAQ_Instance_t *instance, DAQ_Msg_h msg, DAQ_QueryFlow_t *query)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.query_flow.func(instance->api.query_flow.context, msg, query);
}

DAQ_LINKAGE int daq_instance_dp_add_dc(DAQ_Instance_t *instance, DAQ_Msg_h msg, DAQ_DP_key_t *dp_key,
                                        const uint8_t *packet_data, DAQ_Data_Channel_Params_t *params)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.dp_add_dc.func(instance->api.dp_add_dc.context, msg, dp_key, packet_data, params);
}

DAQ_LINKAGE unsigned daq_instance_msg_receive(DAQ_Instance_t *instance, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    if (!instance)
    {
        *rstat = DAQ_RSTAT_INVALID;
        return 0;
    }

    return instance->api.msg_receive.func(instance->api.msg_receive.context, max_recv, msgs, rstat);
}

DAQ_LINKAGE int daq_instance_msg_finalize(DAQ_Instance_t *instance, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.msg_finalize.func(instance->api.msg_finalize.context, msg, verdict);
}

DAQ_LINKAGE int daq_instance_get_msg_pool_info(DAQ_Instance_h instance, DAQ_MsgPoolInfo_t *info)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!info)
        return DAQ_ERROR_INVAL;

    return instance->api.get_msg_pool_info.func(instance->api.get_msg_pool_info.context, info);
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

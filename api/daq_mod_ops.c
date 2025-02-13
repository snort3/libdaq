/*
** Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "daq_api_internal.h"
#include "daq_instance_api_defaults.h"
#include "daq_module_api.h"

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
    struct _daq_instance *instance;     // Backreference to the DAQ instance that this is a part of
    const DAQ_ModuleAPI_t *module;
    void *context;
} DAQ_ModuleInstance_t;

#define DAQ_ERRBUF_SIZE 256
typedef struct _daq_instance
{
    DAQ_ModuleInstance_t *module_instances;
    DAQ_InstanceAPI_t api;
    DAQ_State state;
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
    RESOLVE_INSTANCE_API(api, modinst, inject_relative, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, interrupt, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, stop, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, ioctl, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_stats, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, reset_stats, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_snaplen, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_capabilities, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_datalink_type, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, config_load, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, config_swap, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, config_free, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, msg_receive, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, msg_finalize, default_impl);
    RESOLVE_INSTANCE_API(api, modinst, get_msg_pool_info, default_impl);
}


/*
 * Base API functions that apply to an instantiated configuration go here.
 */

DAQ_Instance_t *daq_modinst_get_instance(DAQ_ModuleInstance_t *modinst)
{
    return modinst->instance;
}

int daq_modinst_resolve_subapi(DAQ_ModuleInstance_t *modinst, DAQ_InstanceAPI_t *api)
{
    if (!modinst->next)
        return DAQ_ERROR_INVAL;

    resolve_instance_api(api, modinst->next, false);

    return DAQ_SUCCESS;
}

void daq_instance_set_errbuf_va(DAQ_Instance_t *instance, const char *format, va_list ap)
{
    vsnprintf(instance->errbuf, sizeof(instance->errbuf), format, ap);
}

void daq_instance_set_errbuf(DAQ_Instance_t *instance, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(instance->errbuf, sizeof(instance->errbuf), format, ap);
    va_end(ap);
}


/*
 * Exported functions that apply to instances of DAQ modules go here.
 */
DAQ_LINKAGE int daq_instance_destroy(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    /* Destroy the module stack from the top down. */
    DAQ_ModuleInstance_t *modinst;
    while ((modinst = instance->module_instances) != NULL)
    {
        instance->module_instances = modinst->next;
        if (modinst->context)
            modinst->module->destroy(modinst->context);
        free(modinst);
    }
    free(instance);

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int daq_instance_instantiate(const DAQ_Config_h config, DAQ_Instance_t **instance_ptr, char *errbuf, size_t len)
{
    /* Don't do this. */
    if (!errbuf)
        return DAQ_ERROR;

    if (!config)
    {
        snprintf(errbuf, len, "Can't instantiate without a configuration!");
        return DAQ_ERROR_INVAL;
    }

    if (!instance_ptr)
    {
        snprintf(errbuf, len, "Can't instantiate without a context pointer!");
        return DAQ_ERROR_INVAL;
    }

    /* Sanity check to make sure that the instance ID configuration is valid. */
    unsigned total_instances = daq_config_get_total_instances(config);
    unsigned instance_id = daq_config_get_instance_id(config);
    if (total_instances && instance_id > total_instances)
    {
        snprintf(errbuf, len, "Can't instantiate with an invalid instance ID!");
        return DAQ_ERROR_INVAL;
    }

    DAQ_ModuleConfig_h modcfg = daq_config_bottom_module_config(config);
    if (!modcfg)
    {
        snprintf(errbuf, len, "Can't instantiate without a module configuration!");
        return DAQ_ERROR_INVAL;
    }

    DAQ_Instance_t *instance = calloc(1, sizeof(*instance));
    if (!instance)
    {
        snprintf(errbuf, len, "Couldn't allocate a new DAQ instance structure!");
        return DAQ_ERROR_NOMEM;
    }
    instance->state = DAQ_STATE_UNINITIALIZED;

    /* Build out the instance from the bottom of the configuration stack up. */
    do {
        DAQ_ModuleInstance_t *modinst = calloc(1, sizeof(*modinst));
        if (!modinst)
        {
            snprintf(errbuf, len, "Couldn't allocate a new DAQ module instance structure!");
            daq_instance_destroy(instance);
            return DAQ_ERROR_NOMEM;
        }

        modinst->instance = instance;
        modinst->module = daq_module_config_get_module(modcfg);

        /* Push this on top of the module instance stack.  This must be done before instantiating
            the module so that it can be referenced inside of that call. */
        modinst->next = instance->module_instances;
        instance->module_instances = modinst;

        int rval = modinst->module->instantiate(modcfg, modinst, &modinst->context);
        if (rval != DAQ_SUCCESS)
        {
            snprintf(errbuf, len, "%s", instance->errbuf);
            daq_instance_destroy(instance);
            return rval;
        }

        modcfg = daq_config_previous_module_config(config);
    } while (modcfg);

    /* Resolve the top-level instance API from the top of the stack with defaults. */
    resolve_instance_api(&instance->api, instance->module_instances, true);

    instance->state = DAQ_STATE_INITIALIZED;

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

    if (instance->state != DAQ_STATE_INITIALIZED)
    {
        daq_instance_set_errbuf(instance, "Can't start an instance that isn't initialized!");
        return DAQ_ERROR;
    }

    int rval = instance->api.start.func(instance->api.start.context);
    if (rval == DAQ_SUCCESS)
        instance->state = DAQ_STATE_STARTED;

    return rval;
}

DAQ_LINKAGE int daq_instance_inject(DAQ_Instance_t *instance, DAQ_MsgType type, const void *hdr,
                                    const uint8_t *data, uint32_t data_len)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!hdr)
    {
        daq_instance_set_errbuf(instance, "No message header given!");
        return DAQ_ERROR_INVAL;
    }

    if (!data)
    {
        daq_instance_set_errbuf(instance, "No message data specified!");
        return DAQ_ERROR_INVAL;
    }

    return instance->api.inject.func(instance->api.inject.context, type, hdr, data, data_len);
}

DAQ_LINKAGE int daq_instance_inject_relative(DAQ_Instance_t *instance, DAQ_Msg_h msg,
                                                const uint8_t *data, uint32_t data_len, int reverse)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!msg)
    {
        daq_instance_set_errbuf(instance, "No original message header given!");
        return DAQ_ERROR_INVAL;
    }

    if (!data)
    {
        daq_instance_set_errbuf(instance, "No message data given!");
        return DAQ_ERROR_INVAL;
    }

    return instance->api.inject_relative.func(instance->api.inject_relative.context, msg, data, data_len, reverse);
}

DAQ_LINKAGE int daq_instance_interrupt(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.interrupt.func(instance->api.interrupt.context);
}

DAQ_LINKAGE int daq_instance_stop(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (instance->state != DAQ_STATE_STARTED)
    {
        daq_instance_set_errbuf(instance, "Can't stop an instance that hasn't started!");
        return DAQ_ERROR;
    }

    int rval = instance->api.stop.func(instance->api.stop.context);
    if (rval == DAQ_SUCCESS)
        instance->state = DAQ_STATE_STOPPED;

    return rval;
}

DAQ_LINKAGE int daq_instance_ioctl(DAQ_Instance_h instance, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.ioctl.func(instance->api.ioctl.context, cmd, arg, arglen);
}

DAQ_LINKAGE DAQ_State daq_instance_check_status(DAQ_Instance_t *instance)
{
    if (!instance)
        return DAQ_STATE_UNKNOWN;

    return instance->state;
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

DAQ_LINKAGE int daq_instance_config_load(DAQ_Instance_t *instance, void **new_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.config_load.func(instance->api.config_load.context, new_config);
}

DAQ_LINKAGE int daq_instance_config_swap(DAQ_Instance_t *instance, void *new_config, void **old_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.config_swap.func(instance->api.config_swap.context, new_config, old_config);
}

DAQ_LINKAGE int daq_instance_config_free(DAQ_Instance_t *instance, void *old_config)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    return instance->api.config_free.func(instance->api.config_free.context, old_config);
}

DAQ_LINKAGE unsigned daq_instance_msg_receive(DAQ_Instance_t *instance, const unsigned max_recv, DAQ_Msg_h msgs[], DAQ_RecvStatus *rstat)
{
    if (!rstat)
    {
        daq_instance_set_errbuf(instance, "No receive status given to set!");
        return 0;
    }

    if (!instance)
    {
        *rstat = DAQ_RSTAT_INVALID;
        return 0;
    }

    if (!msgs)
    {
        daq_instance_set_errbuf(instance, "No message vector given to populate!");
        *rstat = DAQ_RSTAT_INVALID;
        return 0;
    }

    if (!max_recv)
    {
        *rstat = DAQ_RSTAT_OK;
        return 0;
    }

    return instance->api.msg_receive.func(instance->api.msg_receive.context, max_recv, msgs, rstat);
}

DAQ_LINKAGE int daq_instance_msg_finalize(DAQ_Instance_t *instance, DAQ_Msg_h msg, DAQ_Verdict verdict)
{
    if (!instance)
        return DAQ_ERROR_NOCTX;

    if (!msg)
    {
        daq_instance_set_errbuf(instance, "No message given to finalize!");
        return DAQ_ERROR_INVAL;
    }

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

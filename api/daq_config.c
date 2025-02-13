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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "daq.h"
#include "daq_api_internal.h"
#include "daq_common.h"
#include "daq_module_api.h"

typedef struct _daq_dict_entry
{
    char *key;
    char *value;
    struct _daq_dict_entry *next;
} DAQ_DictEntry_t;

typedef struct _daq_dict
{
    DAQ_DictEntry_t *entries;
    DAQ_DictEntry_t *iterator;
} DAQ_Dict_t;

typedef struct _daq_module_config
{
    struct _daq_module_config *next;
    struct _daq_module_config *prev;
    struct _daq_config *config;     /* Backreference to the configuration this is contained within */
    const DAQ_ModuleAPI_t *module;  /* Module that will be instantiated with this configuration */
    DAQ_Mode mode;                  /* Module mode (DAQ_MODE_*) */
    DAQ_Dict_t variables;           /* Dictionary of arbitrary key[:value] string pairs */
} DAQ_ModuleConfig_t;

typedef struct _daq_config
{
    char *input;                    /* Name of the interface(s) or file to be opened */
    uint32_t msg_pool_size;         /* Size of the message pool to create (quantity) */
    int snaplen;                    /* Maximum packet capture length */
    unsigned timeout;               /* Read timeout for acquire loop in milliseconds (0 = unlimited) */
    unsigned total_instances;       /* Total number of concurrent DAQ instances expected (0 = unspecified) */
    unsigned instance_id;           /* ID for the instance to be created (0 = unspecified) */
    DAQ_ModuleConfig_t *module_configs;
    DAQ_ModuleConfig_t *iterator;
} DAQ_Config_t;


/*
 * DAQ Dictionary Functions
 */

static int daq_dict_insert_entry(DAQ_Dict_t *dict, const char *key, const char *value)
{
    DAQ_DictEntry_t *entry;

    entry = calloc(1, sizeof(DAQ_DictEntry_t));
    if (!entry)
        return DAQ_ERROR_NOMEM;
    entry->key = strdup(key);
    if (!entry->key)
    {
        free(entry);
        return DAQ_ERROR_NOMEM;
    }
    if (value)
    {
        entry->value = strdup(value);
        if (!entry->value)
        {
            free(entry->key);
            free(entry);
            return DAQ_ERROR_NOMEM;
        }
    }
    entry->next = dict->entries;
    dict->entries = entry;

    return DAQ_SUCCESS;
}

static DAQ_DictEntry_t *daq_dict_find_entry(DAQ_Dict_t *dict, const char *key)
{
    DAQ_DictEntry_t *entry;

    for (entry = dict->entries; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
            return entry;
    }

    return NULL;
}

static int daq_dict_delete_entry(DAQ_Dict_t *dict, const char *key)
{
    DAQ_DictEntry_t *entry, *prev = NULL;

    for (entry = dict->entries; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
        {
            if (prev)
                prev->next = entry->next;
            else
                dict->entries = entry->next;
            free(entry->key);
            free(entry->value);
            free(entry);
            dict->iterator = NULL;
            return 1;
        }
        prev = entry;
    }

    return 0;
}

static void daq_dict_clear(DAQ_Dict_t *dict)
{
    DAQ_DictEntry_t *entry;

    while ((entry = dict->entries))
    {
        dict->entries = entry->next;
        free(entry->key);
        free(entry->value);
        free(entry);
    }
    dict->iterator = NULL;
}

static DAQ_DictEntry_t *daq_dict_first_entry(DAQ_Dict_t *dict)
{
    dict->iterator = dict->entries;

    return dict->iterator;
}

static DAQ_DictEntry_t *daq_dict_next_entry(DAQ_Dict_t *dict)
{
    if (dict->iterator)
        dict->iterator = dict->iterator->next;

    return dict->iterator;
}


/*
 * DAQ Module Configuration Functions
 */

DAQ_LINKAGE int daq_module_config_new(DAQ_ModuleConfig_t **modcfgptr, const DAQ_ModuleAPI_t *module)
{
    DAQ_ModuleConfig_t *modcfg;

    if (!modcfgptr || !module)
        return DAQ_ERROR_INVAL;

    modcfg = calloc(1, sizeof(DAQ_ModuleConfig_t));
    if (!modcfg)
        return DAQ_ERROR_NOMEM;

    modcfg->module = module;
    *modcfgptr = modcfg;

    return DAQ_SUCCESS;
}

DAQ_Config_t *daq_module_config_get_config(DAQ_ModuleConfig_t *modcfg)
{
    return modcfg->config;
}

DAQ_LINKAGE const DAQ_ModuleAPI_t *daq_module_config_get_module(DAQ_ModuleConfig_t *modcfg)
{
    if (!modcfg)
        return NULL;

    return modcfg->module;
}

DAQ_LINKAGE int daq_module_config_set_mode(DAQ_ModuleConfig_t *modcfg, DAQ_Mode mode)
{
    if (!modcfg)
        return DAQ_ERROR_INVAL;

    if ((mode == DAQ_MODE_PASSIVE && !(modcfg->module->type & DAQ_TYPE_INTF_CAPABLE)) ||
        (mode == DAQ_MODE_INLINE && !(modcfg->module->type & DAQ_TYPE_INLINE_CAPABLE)) ||
        (mode == DAQ_MODE_READ_FILE && !(modcfg->module->type & DAQ_TYPE_FILE_CAPABLE)))
        return DAQ_ERROR_INVAL;

    modcfg->mode = mode;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE DAQ_Mode daq_module_config_get_mode(DAQ_ModuleConfig_t *modcfg)
{
    if (modcfg)
        return modcfg->mode;

    return DAQ_MODE_NONE;
}

DAQ_LINKAGE int daq_module_config_set_variable(DAQ_ModuleConfig_t *modcfg, const char *key, const char *value)
{
    DAQ_DictEntry_t *entry;
    char *new_value;
    int rval;

    if (!modcfg || !key)
        return DAQ_ERROR_INVAL;

    entry = daq_dict_find_entry(&modcfg->variables, key);
    if (entry)
    {
        if (value)
        {
            new_value = strdup(value);
            if (!new_value)
                return DAQ_ERROR_NOMEM;
            if (entry->value)
                free(entry->value);
            entry->value = new_value;
        }
        else if (entry->value)
        {
            free(entry->value);
            entry->value = NULL;
        }
    }
    else if ((rval = daq_dict_insert_entry(&modcfg->variables, key, value)) != DAQ_SUCCESS)
        return rval;

    DEBUG("Set config dictionary entry '%s' => '%s'.\n", key, value);

    return DAQ_SUCCESS;
}

DAQ_LINKAGE const char *daq_module_config_get_variable(DAQ_ModuleConfig_t *modcfg, const char *key)
{
    DAQ_DictEntry_t *entry;

    if (!modcfg || !key)
        return NULL;

    entry = daq_dict_find_entry(&modcfg->variables, key);
    if (!entry)
        return NULL;

    return entry->value;
}

DAQ_LINKAGE int daq_module_config_delete_variable(DAQ_ModuleConfig_t *modcfg, const char *key)
{
    if (!modcfg || !key)
        return DAQ_ERROR_INVAL;

    if (daq_dict_delete_entry(&modcfg->variables, key))
        return DAQ_SUCCESS;

    return DAQ_ERROR;
}

DAQ_LINKAGE int daq_module_config_first_variable(DAQ_ModuleConfig_t *modcfg, const char **key, const char **value)
{
    DAQ_DictEntry_t *entry;

    if (!modcfg || !key || !value)
        return DAQ_ERROR_INVAL;

    entry = daq_dict_first_entry(&modcfg->variables);
    if (entry)
    {
        *key = entry->key;
        *value = entry->value;
    }
    else
    {
        *key = NULL;
        *value = NULL;
    }

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int daq_module_config_next_variable(DAQ_ModuleConfig_t *modcfg, const char **key, const char **value)
{
    DAQ_DictEntry_t *entry;

    if (!modcfg || !key || !value)
        return DAQ_ERROR_INVAL;

    entry = daq_dict_next_entry(&modcfg->variables);
    if (entry)
    {
        *key = entry->key;
        *value = entry->value;
    }
    else
    {
        *key = NULL;
        *value = NULL;
    }
    return DAQ_SUCCESS;
}

DAQ_LINKAGE void daq_module_config_clear_variables(DAQ_ModuleConfig_t *modcfg)
{
    if (!modcfg)
        return;

    daq_dict_clear(&modcfg->variables);
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_module_config_get_next(DAQ_ModuleConfig_t *modcfg)
{
    if (!modcfg)
        return NULL;

    return modcfg->next;
}

DAQ_LINKAGE void daq_module_config_destroy(DAQ_ModuleConfig_t *modcfg)
{
    if (!modcfg)
        return;

    daq_module_config_clear_variables(modcfg);
    free(modcfg);
}


/*
 * DAQ (Top-level) Configuration Functions
 */

DAQ_LINKAGE int daq_config_new(DAQ_Config_t **cfgptr)
{
    DAQ_Config_t *cfg;

    if (!cfgptr)
        return DAQ_ERROR_INVAL;

    cfg = calloc(1, sizeof(DAQ_Config_t));
    if (!cfg)
        return DAQ_ERROR_NOMEM;

    *cfgptr = cfg;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int daq_config_set_input(DAQ_Config_t *cfg, const char *input)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    if (cfg->input)
    {
        free(cfg->input);
        cfg->input = NULL;
    }

    if (input)
    {
        cfg->input = strdup(input);
        if (!cfg->input)
            return DAQ_ERROR_NOMEM;
    }

    return DAQ_SUCCESS;
}

DAQ_LINKAGE const char *daq_config_get_input(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->input;

    return NULL;
}

DAQ_LINKAGE int daq_config_set_msg_pool_size(DAQ_Config_t *cfg, uint32_t num_msgs)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->msg_pool_size = num_msgs;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE uint32_t daq_config_get_msg_pool_size(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->msg_pool_size;

    return 0;
}

DAQ_LINKAGE int daq_config_set_snaplen(DAQ_Config_t *cfg, int snaplen)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->snaplen = snaplen;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE int daq_config_get_snaplen(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->snaplen;

    return 0;
}

DAQ_LINKAGE int daq_config_set_timeout(DAQ_Config_t *cfg, unsigned timeout)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->timeout = timeout;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned daq_config_get_timeout(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->timeout;

    return 0;
}

DAQ_LINKAGE int daq_config_set_total_instances(DAQ_Config_h cfg, unsigned total)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->total_instances = total;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned daq_config_get_total_instances(DAQ_Config_h cfg)
{
    if (cfg)
        return cfg->total_instances;

    return 0;
}

DAQ_LINKAGE int daq_config_set_instance_id(DAQ_Config_h cfg, unsigned id)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->instance_id = id;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE unsigned daq_config_get_instance_id(DAQ_Config_h cfg)
{
    if (cfg)
        return cfg->instance_id;

    return 0;
}

DAQ_LINKAGE int daq_config_push_module_config(DAQ_Config_t *cfg, DAQ_ModuleConfig_t *modcfg)
{
    if (!cfg || !modcfg)
        return DAQ_ERROR_INVAL;

    if (!cfg->module_configs)
    {
        if (modcfg->module->type & DAQ_TYPE_WRAPPER)
            return DAQ_ERROR_INVAL;
    }
    else
    {
        if (!(modcfg->module->type & DAQ_TYPE_WRAPPER))
            return DAQ_ERROR_INVAL;
        cfg->module_configs->prev = modcfg;
        modcfg->next = cfg->module_configs;
    }
    modcfg->config = cfg;
    cfg->module_configs = modcfg;
    cfg->iterator = NULL;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_pop_module_config(DAQ_Config_t *cfg)
{
    DAQ_ModuleConfig_t *modcfg;

    if (!cfg || !cfg->module_configs)
        return NULL;

    modcfg = cfg->module_configs;
    cfg->module_configs = modcfg->next;
    cfg->module_configs->prev = NULL;
    cfg->iterator = NULL;

    modcfg->config = NULL;
    modcfg->next = NULL;

    return modcfg;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_top_module_config(DAQ_Config_t *cfg)
{
    if (!cfg)
        return NULL;

    cfg->iterator = cfg->module_configs;

    return cfg->iterator;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_bottom_module_config(DAQ_Config_t *cfg)
{
    if (!cfg)
        return NULL;

    for (cfg->iterator = cfg->module_configs;
         cfg->iterator && cfg->iterator->next;
         cfg->iterator = cfg->iterator->next);

    return cfg->iterator;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_next_module_config(DAQ_Config_t *cfg)
{
    if (!cfg || !cfg->iterator)
        return NULL;

    cfg->iterator = cfg->iterator->next;

    return cfg->iterator;
}

DAQ_LINKAGE DAQ_ModuleConfig_t *daq_config_previous_module_config(DAQ_Config_t *cfg)
{
    if (!cfg || !cfg->iterator)
        return NULL;

    cfg->iterator = cfg->iterator->prev;

    return cfg->iterator;
}

DAQ_LINKAGE void daq_config_destroy(DAQ_Config_t *cfg)
{
    DAQ_ModuleConfig_t *modcfg;

    if (!cfg)
        return;

    while ((modcfg = cfg->module_configs) != NULL)
    {
        cfg->module_configs = modcfg->next;
        daq_module_config_destroy(modcfg);
    }
    free(cfg->input);
    free(cfg);
}

/*
** Copyright (C) 2015 Cisco and/or its affiliates. All rights reserved.
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
#include "daq_api.h"
#include "daq_api_internal.h"
#include "daq_common.h"

typedef struct _daq_dict_entry
{
    char *key;
    char *value;
    struct _daq_dict_entry *next;
} DAQ_Dict_t;

typedef struct _daq_config
{
    char *input;             /* Name of the interface(s) or file to be opened */
    int snaplen;            /* Maximum packet capture length */
    unsigned timeout;       /* Read timeout for acquire loop in milliseconds (0 = unlimited) */
    DAQ_Mode mode;          /* Module mode (DAQ_MODE_*) */
    uint32_t flags;         /* Other configuration flags (DAQ_CFG_*) */
    DAQ_Dict_t *values;     /* Dictionary of arbitrary key[:value] string pairs. */
    DAQ_Dict_t *curr_variable;    /* Current DAQ variable dictionary iterator position. */
} DAQ_Config_t;

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

DAQ_LINKAGE int daq_config_set_mode(DAQ_Config_t *cfg, DAQ_Mode mode)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->mode = mode;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE DAQ_Mode daq_config_get_mode(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->mode;

    return DAQ_MODE_NONE;
}

DAQ_LINKAGE int daq_config_set_flag(DAQ_Config_t *cfg, uint32_t flag)
{
    if (!cfg)
        return DAQ_ERROR_INVAL;

    cfg->flags |= flag;

    return DAQ_SUCCESS;
}

DAQ_LINKAGE uint32_t daq_config_get_flags(DAQ_Config_t *cfg)
{
    if (cfg)
        return cfg->flags;

    return 0;
}

DAQ_LINKAGE int daq_config_set_variable(DAQ_Config_t *cfg, const char *key, const char *value)
{
    DAQ_Dict_t *entry, *new_entry;
    char *new_value;

    if (!cfg || !key)
        return DAQ_ERROR_INVAL;

    for (entry = cfg->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
            break;
    }

    if (!entry)
    {
        new_entry = calloc(1, sizeof(struct _daq_dict_entry));
        if (!new_entry)
            return DAQ_ERROR_NOMEM;
        new_entry->key = strdup(key);
        if (!new_entry->key)
        {
            free(new_entry);
            return DAQ_ERROR_NOMEM;
        }
        entry = new_entry;
        cfg->curr_variable = NULL;
    }
    else
        new_entry = NULL;

    if (value)
    {
        new_value = strdup(value);
        if (!new_value)
        {
            free(new_entry);
            return DAQ_ERROR_NOMEM;
        }
        if (entry->value)
            free(entry->value);
        entry->value = new_value;
    }
    else if (entry->value)
    {
        free(entry->value);
        entry->value = NULL;
    }

    if (new_entry)
    {
        new_entry->next = cfg->values;
        cfg->values = new_entry;
    }

    DEBUG("Set config dictionary entry '%s' => '%s'.\n", entry->key, entry->value);

    return DAQ_SUCCESS;
}

DAQ_LINKAGE const char *daq_config_get_variable(DAQ_Config_t *cfg, const char *key)
{
    DAQ_Dict_t *entry;

    if (!cfg || !key)
        return NULL;

    for (entry = cfg->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
            return entry->value;
    }

    return NULL;
}

DAQ_LINKAGE void daq_config_delete_variable(DAQ_Config_t *cfg, const char *key)
{
    DAQ_Dict_t *entry, *prev = NULL;

    if (!cfg || !key)
        return;

    for (entry = cfg->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, key))
        {
            if (prev)
                prev->next = entry->next;
            else
                cfg->values = entry->next;
            free(entry->key);
            free(entry->value);
            free(entry);
            cfg->curr_variable = NULL;
            return;
        }
        prev = entry;
    }
}

DAQ_LINKAGE int daq_config_first_variable(DAQ_Config_t *cfg, const char **key, const char **value)
{
    DAQ_Dict_t *entry;

    if (!cfg || !key || !value)
        return DAQ_ERROR_INVAL;

    entry = cfg->curr_variable = cfg->values;
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

DAQ_LINKAGE int daq_config_next_variable(DAQ_Config_t *cfg, const char **key, const char **value)
{
    DAQ_Dict_t *entry;

    if (!cfg || !key || !value || !cfg->curr_variable)
        return DAQ_ERROR_INVAL;

    entry = cfg->curr_variable = cfg->curr_variable->next;
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

DAQ_LINKAGE void daq_config_clear_variables(DAQ_Config_t *cfg)
{
    DAQ_Dict_t *entry;

    if (!cfg)
        return;

    while (cfg->values)
    {
        entry = cfg->values;
        cfg->values = entry->next;
        free(entry->key);
        free(entry->value);
        free(entry);
    }
    cfg->curr_variable = NULL;
}

DAQ_LINKAGE void daq_config_destroy(DAQ_Config_t *cfg)
{
    if (!cfg)
        return;

    free(cfg->input);
    daq_config_clear_variables(cfg);
    free(cfg);
}

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

#ifndef _DAQ_MODULE_API_H
#define _DAQ_MODULE_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <daq_common.h>

typedef int (*daq_module_set_filter_func) (void *handle, const char *filter);
typedef int (*daq_module_start_func) (void *handle);
typedef int (*daq_module_inject_func) (void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len);
typedef int (*daq_module_inject_relative_func) (void *handle, DAQ_Msg_h msg, const uint8_t *data, uint32_t data_len, int reverse);
typedef int (*daq_module_interrupt_func) (void *handle);
typedef int (*daq_module_stop_func) (void *handle);
typedef int (*daq_module_ioctl_func) (void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen);
typedef int (*daq_module_get_stats_func) (void *handle, DAQ_Stats_t *stats);
typedef void (*daq_module_reset_stats_func) (void *handle);
typedef int (*daq_module_get_snaplen_func) (void *handle);
typedef uint32_t (*daq_module_get_capabilities_func) (void *handle);
typedef int (*daq_module_get_datalink_type_func) (void *handle);
typedef int (*daq_module_config_load_func) (void *handle, void **new_config);
typedef int (*daq_module_config_swap_func) (void *handle, void *new_config, void **old_config);
typedef int (*daq_module_config_free_func) (void *handle, void *old_config);
typedef unsigned (*daq_module_msg_receive_func) (void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat);
typedef int (*daq_module_msg_finalize_func) (void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict);
typedef int (*daq_module_get_msg_pool_info_func) (void *handle, DAQ_MsgPoolInfo_t *info);

#define DAQ_INSTANCE_API_STRUCT(fname) struct { daq_module_ ## fname ## _func func; void *context; } fname
typedef struct _daq_instance_api {
    DAQ_INSTANCE_API_STRUCT(set_filter);
    DAQ_INSTANCE_API_STRUCT(start);
    DAQ_INSTANCE_API_STRUCT(inject);
    DAQ_INSTANCE_API_STRUCT(inject_relative);
    DAQ_INSTANCE_API_STRUCT(interrupt);
    DAQ_INSTANCE_API_STRUCT(stop);
    DAQ_INSTANCE_API_STRUCT(ioctl);
    DAQ_INSTANCE_API_STRUCT(get_stats);
    DAQ_INSTANCE_API_STRUCT(reset_stats);
    DAQ_INSTANCE_API_STRUCT(get_snaplen);
    DAQ_INSTANCE_API_STRUCT(get_capabilities);
    DAQ_INSTANCE_API_STRUCT(get_datalink_type);
    DAQ_INSTANCE_API_STRUCT(config_load);
    DAQ_INSTANCE_API_STRUCT(config_swap);
    DAQ_INSTANCE_API_STRUCT(config_free);
    DAQ_INSTANCE_API_STRUCT(msg_receive);
    DAQ_INSTANCE_API_STRUCT(msg_finalize);
    DAQ_INSTANCE_API_STRUCT(get_msg_pool_info);
} DAQ_InstanceAPI_t;


#define DAQ_BASE_API_VERSION    0x00030002

typedef struct _daq_base_api
{
    /* Sanity/Version checking */
    uint32_t api_version;
    uint32_t api_size;
    /* Configuration accessors */
    const char *(*config_get_input) (DAQ_ModuleConfig_h modcfg);
    int (*config_get_snaplen) (DAQ_ModuleConfig_h modcfg);
    unsigned (*config_get_timeout) (DAQ_ModuleConfig_h modcfg);
    unsigned (*config_get_msg_pool_size) (DAQ_ModuleConfig_h modcfg);
    unsigned (*config_get_total_instances) (DAQ_ModuleConfig_h modcfg);
    unsigned (*config_get_instance_id) (DAQ_ModuleConfig_h modcfg);
    DAQ_Mode (*config_get_mode) (DAQ_ModuleConfig_h modcfg);
    const char *(*config_get_variable) (DAQ_ModuleConfig_h modcfg, const char *key);
    int (*config_first_variable) (DAQ_ModuleConfig_h modcfg, const char **key, const char **value);
    int (*config_next_variable) (DAQ_ModuleConfig_h modcfg, const char **key, const char **value);
    /* Module/Instance operations */
    int (*resolve_subapi) (DAQ_ModuleInstance_h modinst, DAQ_InstanceAPI_t *api);
    void (*set_errbuf) (DAQ_ModuleInstance_h modinst, const char *format, ...) __attribute__((format (printf, 2, 3)));
} DAQ_BaseAPI_t;


#define DAQ_MODULE_API_VERSION    0x00030001

typedef struct _daq_module_api
{
    /* The version of the API this module implements. */
    const uint32_t api_version;
    /* The size of this structure (for sanity checking). */
    const uint32_t api_size;
    /* The version of the DAQ module itself - can be completely arbitrary. */
    const uint32_t module_version;
    /* The name of the module (sfpacket, xvnim, pcap, etc.) */
    const char *name;
    /* Various flags describing the module and its capabilities (Inline-capabale, etc.) */
    const uint32_t type;
    /* The function the module loader *must* call first to prepare the module for any other function calls. */
    int (*load) (const DAQ_BaseAPI_t *base_api);
    /* Called when the module is unloaded.  No more calls will be made without calling load() again first. */
    int (*unload) (void);
    /* Get a pointer to an array describing the DAQ variables accepted by this module.
        Returns the size of the retrieved array. */
    int (*get_variable_descs) (const DAQ_VariableDesc_t **var_desc_table);
    /* Instantiate the module with the supplied configuration.  Initialize it as much as possible without
        causing packets to start being queued for the application. */
    int (*instantiate) (const DAQ_ModuleConfig_h config, DAQ_ModuleInstance_h modinst, void **ctxt_ptr);
    /* Clean up and destroy an instantiation of this module. */
    void (*destroy) (void *handle);
    /* Set the module's BPF based on the given string */
    daq_module_set_filter_func set_filter;
    /* Complete device opening and begin queuing packets if they have not been already. */
    daq_module_start_func start;
    /* Spontaneously inject a new message. */
    daq_module_inject_func inject;
    /* Inject a new message going either the same or opposite direction as the specified message. */
    daq_module_inject_relative_func inject_relative;
    /* Attempt to interrupt the current message receive call. */
    daq_module_interrupt_func interrupt;
    /* Stop queuing packets, if possible */
    daq_module_stop_func stop;
    /* Send an I/O control command (read and/or write) */
    daq_module_ioctl_func ioctl;
    /* Populates the <stats> structure with the current DAQ stats.  These stats are cumulative. */
    daq_module_get_stats_func get_stats;
    /* Resets the DAQ module's internal stats. */
    daq_module_reset_stats_func reset_stats;
    /* Return the configured snaplen */
    daq_module_get_snaplen_func get_snaplen;
    /* Return a bitfield of the device's capabilities */
    daq_module_get_capabilities_func get_capabilities;
    /* Return the instance's Data Link Type */
    daq_module_get_datalink_type_func get_datalink_type;
    /* Read new configuration */
    daq_module_config_load_func config_load;
    /* Swap new and old configuration */
    daq_module_config_swap_func config_swap;
    /* Destroy old configuration */
    daq_module_config_free_func config_free;

    daq_module_msg_receive_func msg_receive;
    daq_module_msg_finalize_func msg_finalize;

    /* Query message pool info */
    daq_module_get_msg_pool_info_func get_msg_pool_info;
} DAQ_ModuleAPI_t;

#ifdef __cplusplus
}
#endif

#endif /* _DAQ_MODULE_API_H */

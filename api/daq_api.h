/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

#ifndef _DAQ_API_H
#define _DAQ_API_H

#include <daq_common.h>

typedef struct _daq_module_instance *DAQ_ModuleInstance_h;

typedef int (*daq_module_set_filter_func) (void *handle, const char *filter);
typedef int (*daq_module_start_func) (void *handle);
typedef int (*daq_module_inject_func) (void *handle, DAQ_Msg_h msg, const uint8_t *packet_data, uint32_t len, int reverse);
typedef int (*daq_module_breakloop_func) (void *handle);
typedef int (*daq_module_stop_func) (void *handle);
typedef void (*daq_module_shutdown_func) (void *handle);
typedef int (*daq_module_get_stats_func) (void *handle, DAQ_Stats_t *stats);
typedef void (*daq_module_reset_stats_func) (void *handle);
typedef int (*daq_module_get_snaplen_func) (void *handle);
typedef uint32_t (*daq_module_get_capabilities_func) (void *handle);
typedef int (*daq_module_get_datalink_type_func) (void *handle);
typedef int (*daq_module_get_device_index_func) (void *handle, const char *device);
typedef int (*daq_module_modify_flow_func) (void *handle, DAQ_Msg_h msg, const DAQ_ModFlow_t *modify);
typedef int (*daq_module_hup_prep_func) (void *handle, void **new_config);
typedef int (*daq_module_hup_apply_func) (void *handle, void *new_config, void **old_config);
typedef int (*daq_module_hup_post_func) (void *handle, void *old_config);
typedef int (*daq_module_dp_add_dc_func) (void *handle, DAQ_Msg_h msg, DAQ_DP_key_t *dp_key,
        const uint8_t *packet_data, DAQ_Data_Channel_Params_t *params);
typedef int (*daq_module_query_flow_func) (void *handle, DAQ_Msg_h msg, DAQ_QueryFlow_t *query);
typedef unsigned (*daq_module_msg_receive_func) (void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat);
typedef int (*daq_module_msg_finalize_func) (void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict);
typedef int (*daq_module_get_msg_pool_info_func) (void *handle, DAQ_MsgPoolInfo_t *info);

#define DAQ_INSTANCE_API_STRUCT(fname) struct { daq_module_ ## fname ## _func func; void *context; } fname
typedef struct _daq_instance_api {
    DAQ_INSTANCE_API_STRUCT(set_filter);
    DAQ_INSTANCE_API_STRUCT(start);
    DAQ_INSTANCE_API_STRUCT(inject);
    DAQ_INSTANCE_API_STRUCT(breakloop);
    DAQ_INSTANCE_API_STRUCT(stop);
    DAQ_INSTANCE_API_STRUCT(shutdown);
    DAQ_INSTANCE_API_STRUCT(get_stats);
    DAQ_INSTANCE_API_STRUCT(reset_stats);
    DAQ_INSTANCE_API_STRUCT(get_snaplen);
    DAQ_INSTANCE_API_STRUCT(get_capabilities);
    DAQ_INSTANCE_API_STRUCT(get_datalink_type);
    DAQ_INSTANCE_API_STRUCT(get_device_index);
    DAQ_INSTANCE_API_STRUCT(modify_flow);
    DAQ_INSTANCE_API_STRUCT(query_flow);
    DAQ_INSTANCE_API_STRUCT(hup_prep);
    DAQ_INSTANCE_API_STRUCT(hup_apply);
    DAQ_INSTANCE_API_STRUCT(hup_post);
    DAQ_INSTANCE_API_STRUCT(dp_add_dc);
    DAQ_INSTANCE_API_STRUCT(msg_receive);
    DAQ_INSTANCE_API_STRUCT(msg_finalize);
    DAQ_INSTANCE_API_STRUCT(get_msg_pool_info);
} DAQ_InstanceAPI_t;


#define DAQ_BASE_API_VERSION    0x00030001

typedef struct _daq_base_api
{
    /* Sanity/Version checking */
    uint32_t api_version;
    uint32_t api_size;
    /* Configuration accessors */
    const char *(*config_get_input) (DAQ_Config_h cfg);
    int (*config_get_snaplen) (DAQ_Config_h cfg);
    unsigned (*config_get_timeout) (DAQ_Config_h cfg);
    /* Instance configuration accessors */
    DAQ_Config_h (*module_config_get_config) (DAQ_ModuleConfig_h modcfg);
    unsigned (*module_config_get_msg_pool_size) (DAQ_ModuleConfig_h modcfg);
    DAQ_Mode (*module_config_get_mode) (DAQ_ModuleConfig_h modcfg);
    const char *(*module_config_get_variable) (DAQ_ModuleConfig_h modcfg, const char *key);
    int (*module_config_first_variable) (DAQ_ModuleConfig_h modcfg, const char **key, const char **value);
    int (*module_config_next_variable) (DAQ_ModuleConfig_h modcfg, const char **key, const char **value);
    DAQ_ModuleConfig_h (*module_config_get_next) (DAQ_ModuleConfig_h modcfg);
    /* Module operations */
    int (*module_instantiate) (DAQ_ModuleConfig_h modcfg, DAQ_Instance_h instance);
    /* Module instance operations */
    DAQ_Instance_h (*modinst_get_instance) (DAQ_ModuleInstance_h modinst);
    void (*modinst_resolve_subapi) (DAQ_ModuleInstance_h modinst, DAQ_InstanceAPI_t *api);
    /* Instance operations */
    void (*instance_set_errbuf) (DAQ_Instance_h instance, const char *format, ...);
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
    int (*prepare) (const DAQ_BaseAPI_t *base_api);
    /* Get a pointer to an array describing the DAQ variables accepted by this module.
        Returns the size of the retrieved array. */
    int (*get_variable_descs) (const DAQ_VariableDesc_t **var_desc_table);
    /* Initialize the device for packet acquisition with the supplied configuration.
       This should not start queuing packets for the application. */
    int (*initialize) (const DAQ_ModuleConfig_h config, DAQ_ModuleInstance_h modinst, void **ctxt_ptr);
    /* Set the module's BPF based on the given string */
    daq_module_set_filter_func set_filter;
    /* Complete device opening and begin queuing packets if they have not been already. */
    daq_module_start_func start;
    /* Inject a new packet going either the same or opposite direction as the specified message. */
    daq_module_inject_func inject;
    /* Force breaking out of the acquisition loop after the current iteration. */
    daq_module_breakloop_func breakloop;
    /* Stop queuing packets, if possible */
    daq_module_stop_func stop;
    /* Close the device and clean up */
    daq_module_shutdown_func shutdown;
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
    /* Return the index of the given named device if possible. */
    daq_module_get_device_index_func get_device_index;
    /* Modify a flow */
    daq_module_modify_flow_func modify_flow;
    /* Query a flow */
    daq_module_query_flow_func query_flow;
    /* Read new configuration */
    daq_module_hup_prep_func hup_prep;
    /* Swap new and old configuration */
    daq_module_hup_apply_func hup_apply;
    /* Destroy old configuration */
    daq_module_hup_post_func hup_post;
    /** DAQ API to program a FST/EFT entry for dynamic protocol data channel
     *
     * @param [in] handle      DAQ module handle
     * @param [in] hdr         DAQ packet header of the control channel packet.
     * @param [in] dp_key      Key structure of the data channel flow
     * @param [in] packet_data Packet of the companion control channel packet.
     * @param [in] params      Parameters to control the PST/EFT entry.
     * @return                 Error code of the API. 0 - success.
     */
    daq_module_dp_add_dc_func dp_add_dc;

    daq_module_msg_receive_func msg_receive;
    daq_module_msg_finalize_func msg_finalize;

    /* Query message pool info */
    daq_module_get_msg_pool_info_func get_msg_pool_info;
} DAQ_ModuleAPI_t;


#define DAQ_ERRBUF_SIZE 256

/* This is a convenience macro for safely printing to DAQ error buffers.  It must be called on a known-size character array. */
#ifdef WIN32
inline void DPE(char *var, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    snprintf(var, sizeof(var), ap);

    va_end(ap);
}
#else
#define DPE(var, ...) snprintf(var, sizeof(var), __VA_ARGS__)
#endif

#endif /* _DAQ_API_H */

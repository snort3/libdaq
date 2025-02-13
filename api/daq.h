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

#ifndef _DAQ_H
#define _DAQ_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/socket.h>     // Needed for AF_INET*
#endif

#include <daq_common.h>

/* Library version information functions. */
DAQ_LINKAGE uint32_t daq_version_number(void);
DAQ_LINKAGE const char *daq_version_string(void);

/* Functions for loading, handling, and unloading DAQ modules. */
DAQ_LINKAGE void daq_set_verbosity(int level);
DAQ_LINKAGE int daq_get_verbosity(void);
DAQ_LINKAGE int daq_load_static_modules(DAQ_Module_h *modules);
DAQ_LINKAGE int daq_load_dynamic_modules(const char *module_dirs[]);
DAQ_LINKAGE DAQ_Module_h daq_find_module(const char *name);
DAQ_LINKAGE DAQ_Module_h daq_modules_first(void);
DAQ_LINKAGE DAQ_Module_h daq_modules_next(void);
DAQ_LINKAGE void daq_unload_modules(void);

/* Enumeration to String translation functions. */
DAQ_LINKAGE const char *daq_mode_string(DAQ_Mode mode);
DAQ_LINKAGE const char *daq_state_string(DAQ_State state);
DAQ_LINKAGE const char *daq_verdict_string(DAQ_Verdict verdict);

/* DAQ Module functions. */
DAQ_LINKAGE const char *daq_module_get_name(DAQ_Module_h module);
DAQ_LINKAGE uint32_t daq_module_get_version(DAQ_Module_h module);
DAQ_LINKAGE uint32_t daq_module_get_type(DAQ_Module_h module);
DAQ_LINKAGE int daq_module_get_variable_descs(DAQ_Module_h module, const DAQ_VariableDesc_t **var_desc_table);

/* DAQ Module Configuration Functions */
DAQ_LINKAGE int daq_module_config_new(DAQ_ModuleConfig_h *modcfgptr, DAQ_Module_h module);
DAQ_LINKAGE DAQ_Module_h daq_module_config_get_module(DAQ_ModuleConfig_h modcfg);
DAQ_LINKAGE int daq_module_config_set_mode(DAQ_ModuleConfig_h modcfg, DAQ_Mode mode);
DAQ_LINKAGE DAQ_Mode daq_module_config_get_mode(DAQ_ModuleConfig_h modcfg);
DAQ_LINKAGE int daq_module_config_set_variable(DAQ_ModuleConfig_h modcfg, const char *key, const char *value);
DAQ_LINKAGE const char *daq_module_config_get_variable(DAQ_ModuleConfig_h modcfg, const char *key);
DAQ_LINKAGE int daq_module_config_delete_variable(DAQ_ModuleConfig_h modcfg, const char *key);
DAQ_LINKAGE int daq_module_config_first_variable(DAQ_ModuleConfig_h modcfg, const char **key, const char **value);
DAQ_LINKAGE int daq_module_config_next_variable(DAQ_ModuleConfig_h modcfg, const char **key, const char **value);
DAQ_LINKAGE void daq_module_config_clear_variables(DAQ_ModuleConfig_h modcfg);
DAQ_LINKAGE DAQ_ModuleConfig_h daq_module_config_get_next(DAQ_ModuleConfig_h modcfg);
DAQ_LINKAGE void daq_module_config_destroy(DAQ_ModuleConfig_h modcfg);

/* DAQ Configuration Functions */
DAQ_LINKAGE int daq_config_new(DAQ_Config_h *cfgptr);
DAQ_LINKAGE int daq_config_set_input(DAQ_Config_h cfg, const char *input);
DAQ_LINKAGE const char *daq_config_get_input(DAQ_Config_h cfg);
DAQ_LINKAGE int daq_config_set_msg_pool_size(DAQ_Config_h cfg, uint32_t num_msgs);
DAQ_LINKAGE uint32_t daq_config_get_msg_pool_size(DAQ_Config_h cfg);
DAQ_LINKAGE int daq_config_set_snaplen(DAQ_Config_h cfg, int snaplen);
DAQ_LINKAGE int daq_config_get_snaplen(DAQ_Config_h cfg);
DAQ_LINKAGE int daq_config_set_timeout(DAQ_Config_h cfg, unsigned timeout);
DAQ_LINKAGE unsigned daq_config_get_timeout(DAQ_Config_h cfg);
DAQ_LINKAGE int daq_config_set_total_instances(DAQ_Config_h cfg, unsigned total);
DAQ_LINKAGE unsigned daq_config_get_total_instances(DAQ_Config_h cfg);
DAQ_LINKAGE int daq_config_set_instance_id(DAQ_Config_h cfg, unsigned id);
DAQ_LINKAGE unsigned daq_config_get_instance_id(DAQ_Config_h cfg);
DAQ_LINKAGE int daq_config_push_module_config(DAQ_Config_h cfg, DAQ_ModuleConfig_h modcfg);
DAQ_LINKAGE DAQ_ModuleConfig_h daq_config_pop_module_config(DAQ_Config_h cfg);
DAQ_LINKAGE DAQ_ModuleConfig_h daq_config_top_module_config(DAQ_Config_h cfg);
DAQ_LINKAGE DAQ_ModuleConfig_h daq_config_bottom_module_config(DAQ_Config_h cfg);
DAQ_LINKAGE DAQ_ModuleConfig_h daq_config_next_module_config(DAQ_Config_h cfg);
DAQ_LINKAGE DAQ_ModuleConfig_h daq_config_previous_module_config(DAQ_Config_h cfg);
DAQ_LINKAGE void daq_config_destroy(DAQ_Config_h cfg);

/* DAQ Module Instance functions */
DAQ_LINKAGE int daq_instance_instantiate(const DAQ_Config_h config, DAQ_Instance_h *instance, char *errbuf, size_t len);
DAQ_LINKAGE int daq_instance_destroy(DAQ_Instance_h instance);
DAQ_LINKAGE int daq_instance_set_filter(DAQ_Instance_h instance, const char *filter);
DAQ_LINKAGE int daq_instance_start(DAQ_Instance_h instance);
DAQ_LINKAGE int daq_instance_inject(DAQ_Instance_h instance, DAQ_MsgType type, const void *hdr,
        const uint8_t *data, uint32_t data_len);
DAQ_LINKAGE int daq_instance_inject_relative(DAQ_Instance_h instance, DAQ_Msg_h msg,
        const uint8_t *data, uint32_t data_len, int reverse);
DAQ_LINKAGE int daq_instance_interrupt(DAQ_Instance_h instance);
DAQ_LINKAGE int daq_instance_stop(DAQ_Instance_h instance);
DAQ_LINKAGE int daq_instance_ioctl(DAQ_Instance_h instance, DAQ_IoctlCmd cmd, void *arg, size_t arglen);
DAQ_LINKAGE DAQ_State daq_instance_check_status(DAQ_Instance_h instance);
DAQ_LINKAGE int daq_instance_get_stats(DAQ_Instance_h instance, DAQ_Stats_t *stats);
DAQ_LINKAGE void daq_instance_reset_stats(DAQ_Instance_h instance);
DAQ_LINKAGE int daq_instance_get_snaplen(DAQ_Instance_h instance);
DAQ_LINKAGE uint32_t daq_instance_get_capabilities(DAQ_Instance_h instance);
DAQ_LINKAGE int daq_instance_get_datalink_type(DAQ_Instance_h instance);
DAQ_LINKAGE const char *daq_instance_get_error(DAQ_Instance_h instance);
DAQ_LINKAGE int daq_instance_config_load(DAQ_Instance_h instance, void **new_config);
DAQ_LINKAGE int daq_instance_config_swap(DAQ_Instance_h instance, void *new_config, void **old_config);
DAQ_LINKAGE int daq_instance_config_free(DAQ_Instance_h instance, void *old_config);
DAQ_LINKAGE unsigned daq_instance_msg_receive(DAQ_Instance_h instance, const unsigned max_recv,
        DAQ_Msg_h msgs[], DAQ_RecvStatus *rstat);
DAQ_LINKAGE int daq_instance_msg_finalize(DAQ_Instance_h instance, DAQ_Msg_h msg, DAQ_Verdict verdict);
DAQ_LINKAGE int daq_instance_get_msg_pool_info(DAQ_Instance_h instance, DAQ_MsgPoolInfo_t *info);

/* DAQ Message convenience functions */
static inline DAQ_MsgType daq_msg_get_type(DAQ_Msg_h msg)
{
    return msg->type;
}

static inline size_t daq_msg_get_hdr_len(DAQ_Msg_h msg)
{
    return msg->hdr_len;
}

static inline const void *daq_msg_get_hdr(DAQ_Msg_h msg)
{
    return msg->hdr;
}

static inline const DAQ_PktHdr_t *daq_msg_get_pkthdr(DAQ_Msg_h msg)
{
    return (const DAQ_PktHdr_t *) msg->hdr;
}

static inline uint32_t daq_msg_get_data_len(DAQ_Msg_h msg)
{
    return msg->data_len;
}

static inline uint8_t *daq_msg_get_data(DAQ_Msg_h msg)
{
    return msg->data;
}

static inline const void *daq_msg_get_meta(DAQ_Msg_h msg, uint8_t slot)
{
    return msg->meta[slot];
}

static inline int daq_napt_info_src_addr_family(const DAQ_NAPTInfo_t *napti)
{
    return (napti->flags & DAQ_NAPT_INFO_FLAG_SIP_V6) ? AF_INET6 : AF_INET;
}

static inline int daq_napt_info_dst_addr_family(const DAQ_NAPTInfo_t *napti)
{
    return (napti->flags & DAQ_NAPT_INFO_FLAG_DIP_V6) ? AF_INET6 : AF_INET;
}

static inline const void *daq_msg_get_priv_data(DAQ_Msg_h msg)
{
    return msg->priv;
}

#ifdef __cplusplus
}
#endif

#endif /* _DAQ_H */

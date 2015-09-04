/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2010-2013 Sourcefire, Inc.
** Author: Michael R. Altizer <maltizer@sourcefire.com>
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

#include <stdio.h>
#include <daq_common.h>

#define DAQ_VERSION 3

typedef const struct _daq_module *DAQ_Module_h;

/* Functions for loading, handling, and unloading DAQ modules. */
DAQ_LINKAGE void daq_set_verbosity(int level);
DAQ_LINKAGE int daq_load_modules(const char *module_dirs[]);
DAQ_LINKAGE DAQ_Module_h daq_find_module(const char *name);
DAQ_LINKAGE DAQ_Module_h daq_modules_first(void);
DAQ_LINKAGE DAQ_Module_h daq_modules_next(void);
DAQ_LINKAGE void daq_unload_modules(void);
DAQ_LINKAGE void daq_print_stats(DAQ_Stats_t *stats, FILE *fp);

/* Enumeration to String translation functions. */
DAQ_LINKAGE const char *daq_mode_string(DAQ_Mode mode);
DAQ_LINKAGE const char *daq_state_string(DAQ_State state);
DAQ_LINKAGE const char *daq_verdict_string(DAQ_Verdict verdict);

/* DAQ Module functions. */
DAQ_LINKAGE const char *daq_get_name(const DAQ_Module_h module);
DAQ_LINKAGE uint32_t daq_get_version(const DAQ_Module_h module);
DAQ_LINKAGE uint32_t daq_get_type(const DAQ_Module_h module);
DAQ_LINKAGE int daq_get_variable_descriptions(const DAQ_Module_h module, const DAQ_VariableDesc_t **var_desc_table);

/* DAQ Module Instance functions */
DAQ_LINKAGE int daq_initialize(const DAQ_Module_h module, const DAQ_Config_h config, void **handle, char *errbuf, size_t len);
DAQ_LINKAGE int daq_set_filter(const DAQ_Module_h module, void *handle, const char *filter);
DAQ_LINKAGE int daq_start(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE int daq_inject(const DAQ_Module_h module, void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse);
DAQ_LINKAGE int daq_breakloop(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE int daq_stop(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE int daq_shutdown(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE DAQ_State daq_check_status(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE int daq_get_stats(const DAQ_Module_h module, void *handle, DAQ_Stats_t *stats);
DAQ_LINKAGE void daq_reset_stats(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE int daq_get_snaplen(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE uint32_t daq_get_capabilities(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE int daq_get_datalink_type(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE const char *daq_get_error(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE void daq_clear_error(const DAQ_Module_h module, void *handle);
DAQ_LINKAGE int daq_modify_flow(const DAQ_Module_h module, void *handle, const DAQ_PktHdr_t *hdr, const DAQ_ModFlow_t *modify);
DAQ_LINKAGE int daq_query_flow(const DAQ_Module_h module, void *handle, const DAQ_PktHdr_t *hdr, DAQ_QueryFlow_t *query);
DAQ_LINKAGE int daq_hup_prep(const DAQ_Module_h module, void *handle, void **new_config);
DAQ_LINKAGE int daq_hup_apply(const DAQ_Module_h module, void *handle, void *new_config, void **old_config);
DAQ_LINKAGE int daq_hup_post(const DAQ_Module_h module, void *handle, void *old_config);
DAQ_LINKAGE int daq_dp_add_dc(const DAQ_Module_h module, void *handle, const DAQ_PktHdr_t *hdr, DAQ_DP_key_t *dp_key, const uint8_t *packet_data);
DAQ_LINKAGE int daq_msg_receive(const DAQ_Module_h module, void *handle, const DAQ_Msg_t **msgptr);
DAQ_LINKAGE int daq_msg_finalize(const DAQ_Module_h module, void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict);
DAQ_LINKAGE DAQ_PktHdr_t *daq_packet_header_from_msg(const DAQ_Module_h module, void *handle, const DAQ_Msg_t *msg);
DAQ_LINKAGE const uint8_t *daq_packet_data_from_msg(const DAQ_Module_h module, void *handle, const DAQ_Msg_t *msg);

#endif /* _DAQ_H */

/*
** Copyright (C) 2018 Cisco and/or its affiliates. All rights reserved.
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

#include "daq_common.h"
    
int daq_default_set_filter(void *handle, const char *filter);
int daq_default_inject(void *handle, DAQ_Msg_h msg, const uint8_t *packet_data, uint32_t len, int reverse);
int daq_default_breakloop(void *handle);
int daq_default_get_stats(void *handle, DAQ_Stats_t *stats);
void daq_default_reset_stats(void *handle);
int daq_default_get_snaplen(void *handle);
uint32_t daq_default_get_capabilities(void *handle);
int daq_default_get_datalink_type(void *handle);
int daq_default_get_device_index(void *handle, const char *device);
int daq_default_modify_flow(void *handle, DAQ_Msg_h msg, const DAQ_ModFlow_t *modify);
int daq_default_config_load(void *handle, void **new_config);
int daq_default_config_swap(void *handle, void *new_config, void **old_config);
int daq_default_config_free(void *handle, void *old_config);
int daq_default_dp_add_dc(void *handle, DAQ_Msg_h msg, DAQ_DP_key_t *dp_key,
        const uint8_t *packet_data, DAQ_Data_Channel_Params_t *params);
int daq_default_query_flow(void *handle, DAQ_Msg_h msg, DAQ_QueryFlow_t *query);
unsigned daq_default_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat);
int daq_default_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict);
int daq_default_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info);

/*
** Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "daq_dlt.h"
#include "daq_instance_api_defaults.h"

int daq_default_set_filter(void *handle, const char *filter)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_start(void *handle)
{
    return DAQ_SUCCESS;
}

int daq_default_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_inject_relative(void *handle, DAQ_Msg_h msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_interrupt(void *handle)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_stop(void *handle)
{
    return DAQ_SUCCESS;
}

int daq_default_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_get_stats(void *handle, DAQ_Stats_t *stats)
{
    return DAQ_ERROR_NOTSUP;
}

void daq_default_reset_stats(void *handle)
{
}

int daq_default_get_snaplen(void *handle)
{
    return -1;
}

uint32_t daq_default_get_capabilities(void *handle)
{
    return 0;
}

int daq_default_get_datalink_type(void *handle)
{
    return DLT_NULL;
}

int daq_default_config_load(void *handle, void **new_config)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_config_swap(void *handle, void *new_config, void **old_config)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_config_free(void *handle, void *old_config)
{
    return DAQ_ERROR_NOTSUP;
}

unsigned daq_default_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    return DAQ_ERROR_NOTSUP;
}

int daq_default_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    return DAQ_ERROR_NOTSUP;
}

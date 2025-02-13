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

#include "daq_test_module.h"

#include <daq_dlt.h>

static int daq_test_module_load(const DAQ_BaseAPI_t *base_api)
{
    return DAQ_SUCCESS;
}

static int daq_test_module_unload(void)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = NULL;
    return 0;
}

static int daq_test_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    return DAQ_SUCCESS;
}

static void daq_test_destroy(void *handle)
{
}

static int daq_test_start(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    return DAQ_SUCCESS;
}

static int daq_test_inject_relative(void *handle, DAQ_Msg_h msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    return DAQ_SUCCESS;
}

static int daq_test_interrupt(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_stop(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_stats(void *handle, DAQ_Stats_t *stats)
{
    return DAQ_SUCCESS;
}

static void daq_test_reset_stats(void *handle)
{
}

static int daq_test_get_snaplen(void *handle)
{
    return DAQ_SUCCESS;
}

static uint32_t daq_test_get_capabilities(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_datalink_type(void *handle)
{
    return DLT_NULL;
}

static unsigned daq_test_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    return 0;
}

static int daq_test_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    return DAQ_SUCCESS;
}


DAQ_ModuleAPI_t test_module =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ TEST_MODULE_VERSION,
    /* .name = */ TEST_MODULE_NAME,
    /* .type = */ TEST_MODULE_TYPE,
    /* .load = */ daq_test_module_load,
    /* .unload = */ daq_test_module_unload,
    /* .get_variable_descs = */ daq_test_get_variable_descs,
    /* .instantiate = */ daq_test_instantiate,
    /* .destroy = */ daq_test_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ daq_test_start,
    /* .inject = */ daq_test_inject,
    /* .inject_relative = */ daq_test_inject_relative,
    /* .interrupt = */ daq_test_interrupt,
    /* .stop = */ daq_test_stop,
    /* .ioctl = */ NULL,
    /* .get_stats = */ daq_test_get_stats,
    /* .reset_stats = */ daq_test_reset_stats,
    /* .get_snaplen = */ daq_test_get_snaplen,
    /* .get_capabilities = */ daq_test_get_capabilities,
    /* .get_datalink_type = */ daq_test_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ daq_test_msg_receive,
    /* .msg_finalize = */ daq_test_msg_finalize,
    /* .get_msg_pool_info = */ NULL,
};


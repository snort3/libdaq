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

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "daq_module_api.h"

#define DAQ_BPF_VERSION 1

#ifndef PCAP_NETMASK_UNKNOWN // For OpenBSD
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

#define CALL_SUBAPI_NOARGS(ctxt, fname) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context)

#define CALL_SUBAPI(ctxt, fname, ...) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context, __VA_ARGS__)

typedef struct
{
    /* Configuration */
    char *filter;
    int snaplen;
    /* State */
    DAQ_ModuleInstance_h modinst;
    DAQ_InstanceAPI_t subapi;
    struct bpf_program fcode;
    uint64_t filtered;
} BPF_Context_t;

static DAQ_BaseAPI_t daq_base_api;
static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;


static int bpf_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int bpf_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int bpf_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    BPF_Context_t *bc;

    bc = calloc(1, sizeof(*bc));
    if (!bc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the DAQ context", __func__);
        return DAQ_ERROR_NOMEM;
    }
    bc->modinst = modinst;

    if (daq_base_api.resolve_subapi(modinst, &bc->subapi) != DAQ_SUCCESS)
    {
        SET_ERROR(modinst, "%s: Couldn't resolve subapi. No submodule configured?", __func__);
        free(bc);
        return DAQ_ERROR_INVAL;
    }

    bc->snaplen = daq_base_api.config_get_snaplen(modcfg);

    *ctxt_ptr = bc;

    return DAQ_SUCCESS;
}

static void bpf_daq_destroy(void *handle)
{
    BPF_Context_t *bc = (BPF_Context_t *) handle;

    if (bc->filter)
        free(bc->filter);
    pcap_freecode(&bc->fcode);
    free(bc);
}

static int bpf_daq_set_filter(void *handle, const char *filter)
{
    BPF_Context_t *bc = (BPF_Context_t *) handle;
    struct bpf_program fcode;

    if (bc->filter)
        free(bc->filter);

    bc->filter = strdup(filter);
    if (!bc->filter)
    {
        SET_ERROR(bc->modinst, "%s: Couldn't allocate memory for the filter string!", __func__);
        return DAQ_ERROR;
    }

    pthread_mutex_lock(&bpf_mutex);
    /* FIXIT-M Should really try to get actual snaplen and DLT from submodule */
    if (pcap_compile_nopcap(bc->snaplen, DLT_EN10MB, &fcode, bc->filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
        pthread_mutex_unlock(&bpf_mutex);
        SET_ERROR(bc->modinst, "%s: BPF state machine compilation failed!", __func__);
        return DAQ_ERROR;
    }
    pthread_mutex_unlock(&bpf_mutex);

    pcap_freecode(&bc->fcode);
    bc->fcode.bf_len = fcode.bf_len;
    bc->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int bpf_daq_get_stats(void* handle, DAQ_Stats_t* stats)
{
    BPF_Context_t *bc = (BPF_Context_t *) handle;
    int rval = CALL_SUBAPI(bc, get_stats, stats);

    /* Update for our reckoning of the packets we've filtered. */
    if (rval == DAQ_SUCCESS)
    {
        stats->packets_received -= bc->filtered;
        stats->packets_filtered = bc->filtered;
        stats->verdicts[DAQ_VERDICT_PASS] -= bc->filtered;
    }

    return rval;
}

static void bpf_daq_reset_stats(void* handle)
{
    BPF_Context_t *bc = (BPF_Context_t *) handle;
    CALL_SUBAPI_NOARGS(bc, reset_stats);
    bc->filtered = 0;
}

static uint32_t bpf_daq_get_capabilities(void* handle)
{
    BPF_Context_t *bc = (BPF_Context_t *) handle;
    uint32_t caps = CALL_SUBAPI_NOARGS(bc, get_capabilities);
    caps |= DAQ_CAPA_BPF;
    return caps;
}

static unsigned bpf_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    BPF_Context_t *bc = (BPF_Context_t *) handle;
    unsigned num_receive = CALL_SUBAPI(bc, msg_receive, max_recv, msgs, rstat);

    /* If we never had a filter set, just return the results unmodified. */
    if (!bc->fcode.bf_insns)
        return num_receive;

    unsigned num_receive_filtered = num_receive;

    for (unsigned idx = 0; idx < num_receive; idx++)
    {
        const DAQ_Msg_t *msg = msgs[idx];

        if (msg->type != DAQ_MSG_TYPE_PACKET)
            continue;

        const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;

        if (bpf_filter(bc->fcode.bf_insns, msg->data, hdr->pktlen, msg->data_len) == 0)
        {
            /* FIXIT-L Check return code for finalizing messages and return some sort of error if it fails */
            CALL_SUBAPI(bc, msg_finalize, msg, DAQ_VERDICT_PASS);
            msgs[idx] = NULL;
            bc->filtered++;
            num_receive_filtered--;
        }
    }

    /* Fix up the array if we filtered any of the entries. */
    if (num_receive != num_receive_filtered)
    {
        unsigned idx, next_idx;

        for (idx = 0, next_idx = 0; idx < num_receive_filtered; next_idx++)
        {
            if (!msgs[idx])
            {
                if (!msgs[next_idx])
                    continue;
                msgs[idx] = msgs[next_idx];
                msgs[next_idx] = NULL;
            }
            idx++;
        }
    }

    return num_receive_filtered;
}


#ifdef BUILDING_SO
DAQ_SO_PUBLIC DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
DAQ_ModuleAPI_t bpf_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_BPF_VERSION,
    /* .name = */ "bpf",
    /* .type = */ DAQ_TYPE_WRAPPER | DAQ_TYPE_INLINE_CAPABLE,
    /* .load = */ bpf_daq_module_load,
    /* .unload = */ bpf_daq_module_unload,
    /* .get_variable_descs = */ NULL,
    /* .instantiate = */ bpf_daq_instantiate,
    /* .destroy = */ bpf_daq_destroy,
    /* .set_filter = */ bpf_daq_set_filter,
    /* .start = */ NULL,
    /* .inject = */ NULL,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ NULL,
    /* .stop = */ NULL,
    /* .ioctl = */ NULL,
    /* .get_stats = */ bpf_daq_get_stats,
    /* .reset_stats = */ bpf_daq_reset_stats,
    /* .get_snaplen = */ NULL,
    /* .get_capabilities = */ bpf_daq_get_capabilities,
    /* .get_datalink_type = */ NULL,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ bpf_daq_msg_receive,
    /* .msg_finalize = */ NULL,
    /* .get_msg_pool_info = */ NULL,
};


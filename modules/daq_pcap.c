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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef WIN32
#include <sys/types.h>
#include <netinet/in.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>
#ifdef HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
#endif /* HAVE_LINUX_IF_PACKET_H */
#include <unistd.h>

#include "daq_api.h"

#define DAQ_PCAP_VERSION 4

#define DEFAULT_POOL_SIZE 16
#define DAQ_PCAP_ROLLOVER_LIM 1000000000 //Check for rollover every billionth packet

typedef struct _pcap_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    struct _pcap_pkt_desc *next;
} PcapPktDesc;

typedef struct _pcap_context
{
    /* Configuration */
    char *device;
    char *filter_string;
    int snaplen;
    unsigned pool_size;
    bool promisc_mode;
    bool immediate_mode;
    int timeout;
    int buffer_size;
    DAQ_Mode mode;
    /* State */
    DAQ_Instance_h instance;
    DAQ_Stats_t stats;
    DAQ_State state;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    PcapPktDesc *pool;
    PcapPktDesc *pkt_freelist;
    pcap_t *handle;
    FILE *fp;
    uint32_t netmask;
    bool nonblocking;
    /* Stats tracking */
    uint32_t base_recv;
    uint32_t base_drop;
    uint64_t rollover_recv;
    uint64_t rollover_drop;
    uint32_t wrap_recv;
    uint32_t wrap_drop;
    uint32_t hwupdate_count;
} Pcap_Context_t;

static void pcap_daq_reset_stats(void *handle);

static DAQ_VariableDesc_t pcap_variable_descriptions[] = {
    { "buffer_size", "Packet buffer space to allocate in bytes", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "no_promiscuous", "Disables opening the interface in promiscuous mode", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "no_immediate", "Disables immediate mode for traffic capture (may cause unbounded blocking)", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

static DAQ_BaseAPI_t daq_base_api;

static void destroy_packet_pool(Pcap_Context_t *context)
{
    if (context->pool)
    {
        while (context->pool_size > 0)
            free(context->pool[--context->pool_size].data);
        free(context->pool);
        context->pool = NULL;
    }
    context->pkt_freelist = NULL;
}

static int create_packet_pool(Pcap_Context_t *context, unsigned size)
{
    context->pool = calloc(sizeof(PcapPktDesc), size);
    if (!context->pool)
    {
        daq_base_api.instance_set_errbuf(context->instance, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(PcapPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    while (context->pool_size < size)
    {
        /* Allocate packet data and set up descriptor */
        PcapPktDesc *desc = &context->pool[context->pool_size];
        desc->data = malloc(context->snaplen);
        if (!desc->data)
        {
            daq_base_api.instance_set_errbuf(context->instance, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                    __func__, sizeof(PcapPktDesc) * size);
            return DAQ_ERROR_NOMEM;
        }

        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->msg = desc;

        /* Place it on the free list */
        desc->next = context->pkt_freelist;
        context->pkt_freelist = desc;

        context->pool_size++;
    }
    return DAQ_SUCCESS;
}

static int update_hw_stats(Pcap_Context_t *context)
{
    struct pcap_stat ps;

    if (context->handle && context->device)
    {
        memset(&ps, 0, sizeof(struct pcap_stat));
        if (pcap_stats(context->handle, &ps) == -1)
        {
            daq_base_api.instance_set_errbuf(context->instance, "%s", pcap_geterr(context->handle));
            return DAQ_ERROR;
        }

        /* PCAP receive counter wrapped */
        if (ps.ps_recv < context->wrap_recv)
            context->rollover_recv += UINT32_MAX;

        /* PCAP drop counter wrapped */
        if (ps.ps_drop < context->wrap_drop)
            context->rollover_drop += UINT32_MAX;

        context->wrap_recv = ps.ps_recv;
        context->wrap_drop = ps.ps_drop;

        context->stats.hw_packets_received = context->rollover_recv + context->wrap_recv - context->base_recv;
        context->stats.hw_packets_dropped = context->rollover_drop + context->wrap_drop - context->base_drop;
        context->hwupdate_count = 0;
    }

    return DAQ_SUCCESS;
}

static inline int set_nonblocking(Pcap_Context_t *context, bool nonblocking)
{
    if (nonblocking != context->nonblocking)
    {
        int status;
        if ((status = pcap_setnonblock(context->handle, nonblocking ? 1 : 0, context->pcap_errbuf)) < 0)
        {
            daq_base_api.instance_set_errbuf(context->instance, "%s", context->pcap_errbuf);
            return status;
        }
        context->nonblocking = nonblocking;
    }
    return 0;
}

static int pcap_daq_prepare(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int pcap_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = pcap_variable_descriptions;

    return sizeof(pcap_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int pcap_daq_initialize(const DAQ_ModuleConfig_h config, DAQ_Instance_h instance)
{
    Pcap_Context_t *context;
    const char *varKey, *varValue;

    context = calloc(1, sizeof(Pcap_Context_t));
    if (!context)
    {
        daq_base_api.instance_set_errbuf(instance, "%s: Couldn't allocate memory for the new PCAP context!", __func__);
        return DAQ_ERROR_NOMEM;
    }
    context->instance = instance;

    context->snaplen = daq_base_api.module_config_get_snaplen(config);
    context->timeout = daq_base_api.module_config_get_timeout(config);
    context->promisc_mode = true;
    context->immediate_mode = true;

    daq_base_api.module_config_first_variable(config, &varKey, &varValue);
    while (varKey)
    {
        /* Retrieve the requested buffer size (default = 0) */
        if (!strcmp(varKey, "buffer_size"))
            context->buffer_size = strtol(varValue, NULL, 10);
        else if (!strcmp(varKey, "no_promiscuous"))
            context->promisc_mode = false;
        else if (!strcmp(varKey, "no_immediate"))
            context->immediate_mode = false;

        daq_base_api.module_config_next_variable(config, &varKey, &varValue);
    }

    int rval = create_packet_pool(context, DEFAULT_POOL_SIZE);
    if (rval != DAQ_SUCCESS)
    {
        destroy_packet_pool(context);
        free(context);
        return rval;
    }

    context->mode = daq_base_api.module_config_get_mode(config);
    if (context->mode == DAQ_MODE_READ_FILE)
    {
        context->fp = fopen(daq_base_api.module_config_get_input(config), "rb");
        if (!context->fp)
        {
            daq_base_api.instance_set_errbuf(instance, "%s: Couldn't open file '%s' for reading: %s", __func__,
                    daq_base_api.module_config_get_input(config), strerror(errno));
            destroy_packet_pool(context);
            free(context);
            return DAQ_ERROR_NOMEM;
        }
    }
    else
    {
        context->device = strdup(daq_base_api.module_config_get_input(config));
        if (!context->device)
        {
            daq_base_api.instance_set_errbuf(instance, "%s: Couldn't allocate memory for the device string!", __func__);
            destroy_packet_pool(context);
            free(context);
            return DAQ_ERROR_NOMEM;
        }
    }

    context->hwupdate_count = 0;
    context->state = DAQ_STATE_INITIALIZED;

    daq_base_api.instance_set_context(context->instance, context);

    return DAQ_SUCCESS;
}

static int pcap_daq_install_filter(Pcap_Context_t *context, const char *filter)
{
    struct bpf_program fcode;

    if (pcap_compile(context->handle, &fcode, filter, 1, context->netmask) < 0)
    {
        daq_base_api.instance_set_errbuf(context->instance, "%s: pcap_compile: %s", __func__, pcap_geterr(context->handle));
        return DAQ_ERROR;
    }

    if (pcap_setfilter(context->handle, &fcode) < 0)
    {
        pcap_freecode(&fcode);
        daq_base_api.instance_set_errbuf(context->instance, "%s: pcap_setfilter: %s", __func__, pcap_geterr(context->handle));
        return DAQ_ERROR;
    }

    pcap_freecode(&fcode);

    return DAQ_SUCCESS;
}

static int pcap_daq_set_filter(void *handle, const char *filter)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;
    struct bpf_program fcode;
    pcap_t *dead_handle;
    int rval;

    if (context->handle)
    {
        if ((rval = pcap_daq_install_filter(handle, filter)) != 0)
            return rval;
    }
    else
    {
        /* Try to validate the BPF with a dead PCAP handle. */
        dead_handle = pcap_open_dead(DLT_EN10MB, context->snaplen);
        if (!dead_handle)
        {
            daq_base_api.instance_set_errbuf(context->instance, "%s: Could not allocate a dead PCAP handle!", __func__);
            return DAQ_ERROR_NOMEM;
        }
        if (pcap_compile(dead_handle, &fcode, filter, 1, context->netmask) < 0)
        {
            daq_base_api.instance_set_errbuf(context->instance, "%s: pcap_compile: %s", __func__, pcap_geterr(dead_handle));
            return DAQ_ERROR;
        }
        pcap_freecode(&fcode);
        pcap_close(dead_handle);

        /* Store the BPF string for later. */
        if (context->filter_string)
            free(context->filter_string);
        context->filter_string = strdup(filter);
        if (!context->filter_string)
        {
            daq_base_api.instance_set_errbuf(context->instance, "%s: Could not allocate space to store a copy of the filter string!", __func__);
            return DAQ_ERROR_NOMEM;
        }
    }

    return DAQ_SUCCESS;
}

static int pcap_daq_start(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;
    uint32_t localnet, netmask;
    uint32_t defaultnet = 0xFFFFFF00;
    int status;

    if (context->device)
    {
        context->handle = pcap_create(context->device, context->pcap_errbuf);
        if (!context->handle)
            goto fail;
        if ((status = pcap_set_immediate_mode(context->handle, context->immediate_mode ? 1 : 0)) < 0)
            goto fail;
        if ((status = pcap_set_snaplen(context->handle, context->snaplen)) < 0)
            goto fail;
        if ((status = pcap_set_promisc(context->handle, context->promisc_mode ? 1 : 0)) < 0)
            goto fail;
        if ((status = pcap_set_timeout(context->handle, context->timeout)) < 0)
            goto fail;
        if ((status = pcap_set_buffer_size(context->handle, context->buffer_size)) < 0)
            goto fail;
        if ((status = pcap_activate(context->handle)) < 0)
            goto fail;
        if ((status = set_nonblocking(context, true)) < 0)
            goto fail;
        if (pcap_lookupnet(context->device, &localnet, &netmask, context->pcap_errbuf) < 0)
            netmask = htonl(defaultnet);
    }
    else
    {
        context->handle = pcap_fopen_offline(context->fp, context->pcap_errbuf);
        if (!context->handle)
            goto fail;
        context->fp = NULL;

        netmask = htonl(defaultnet);
    }
    context->netmask = netmask;

    if (context->filter_string)
    {
        if ((status = pcap_daq_install_filter(context, context->filter_string)) != DAQ_SUCCESS)
        {
            pcap_close(context->handle);
            context->handle = NULL;
            return status;
        }
        free(context->filter_string);
        context->filter_string = NULL;
    }

    pcap_daq_reset_stats(handle);

    context->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;

fail:
    if (context->handle)
    {
        if (status == PCAP_ERROR || status == PCAP_ERROR_NO_SUCH_DEVICE || status == PCAP_ERROR_PERM_DENIED)
            daq_base_api.instance_set_errbuf(context->instance, "%s", pcap_geterr(context->handle));
        else
            daq_base_api.instance_set_errbuf(context->instance, "%s: %s", context->device, pcap_statustostr(status));
        pcap_close(context->handle);
        context->handle = NULL;
    }
    else
        daq_base_api.instance_set_errbuf(context->instance, "%s", context->pcap_errbuf);
    return DAQ_ERROR;
}

static int pcap_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;

    if (pcap_inject(context->handle, packet_data, len) < 0)
    {
        daq_base_api.instance_set_errbuf(context->instance, "%s", pcap_geterr(context->handle));
        return DAQ_ERROR;
    }

    context->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int pcap_daq_breakloop(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;

    if (!context->handle)
        return DAQ_ERROR;

    pcap_breakloop(context->handle);

    return DAQ_SUCCESS;
}

static int pcap_daq_stop(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;

    if (context->handle)
    {
        /* Store the hardware stats for post-stop stat calls. */
        update_hw_stats(context);
        pcap_close(context->handle);
        context->handle = NULL;
    }

    context->state = DAQ_STATE_STOPPED;

    return DAQ_SUCCESS;
}

static void pcap_daq_shutdown(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;

    if (context->handle)
        pcap_close(context->handle);
    if (context->fp)
        fclose(context->fp);
    if (context->device)
        free(context->device);
    if (context->filter_string)
        free(context->filter_string);
    destroy_packet_pool(context);
    free(context);
}

static DAQ_State pcap_daq_check_status(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;

    return context->state;
}

static int pcap_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;

    if (update_hw_stats(context) != DAQ_SUCCESS)
        return DAQ_ERROR;

    memcpy(stats, &context->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void pcap_daq_reset_stats(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;
    struct pcap_stat ps;

    memset(&context->stats, 0, sizeof(DAQ_Stats_t));

    if (!context->handle)
        return;

    memset(&ps, 0, sizeof(struct pcap_stat));
    if (context->handle && context->device && pcap_stats(context->handle, &ps) == 0)
    {
        context->base_recv = context->wrap_recv = ps.ps_recv;
        context->base_drop = context->wrap_drop = ps.ps_drop;
    }
}

static int pcap_daq_get_snaplen(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;

    if (context->handle)
        return pcap_snapshot(context->handle);

    return context->snaplen;
}

static uint32_t pcap_daq_get_capabilities(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;
    uint32_t capabilities = DAQ_CAPA_BPF | DAQ_CAPA_BREAKLOOP;

    if (context->device)
        capabilities |= DAQ_CAPA_INJECT;

    return capabilities;
}

static int pcap_daq_get_datalink_type(void *handle)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;

    if (context->handle)
        return pcap_datalink(context->handle);

    return DLT_NULL;
}

static int pcap_daq_get_device_index(void *handle, const char *device)
{
    return DAQ_ERROR_NOTSUP;
}

static unsigned pcap_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    struct pcap_pkthdr *pcaphdr;
    Pcap_Context_t *context = (Pcap_Context_t *) handle;
    const u_char *data;
    unsigned idx;

    *rstat = DAQ_RSTAT_OK;
    for (idx = 0; idx < max_recv; idx++)
    {
        /* Make sure that we have a packet descriptor available to populate *before*
            calling into libpcap. */
        PcapPktDesc *desc = context->pkt_freelist;
        if (!desc)
        {
            *rstat = DAQ_RSTAT_NOBUF;
            break;
        }

        /* When dealing with a live interface, try to get the first packet in non-blocking mode.
            If there's nothing to receive, switch to blocking mode. */
        int pcap_rval;
        if (context->mode != DAQ_MODE_READ_FILE && idx == 0)
        {
            if (set_nonblocking(context, true) != DAQ_SUCCESS)
            {
                *rstat = DAQ_RSTAT_ERROR;
                break;
            }
            pcap_rval = pcap_next_ex(context->handle, &pcaphdr, &data);
            if (pcap_rval == 0)
            {
                if (set_nonblocking(context, false) != DAQ_SUCCESS)
                {
                    *rstat = DAQ_RSTAT_ERROR;
                    break;
                }
                pcap_rval = pcap_next_ex(context->handle, &pcaphdr, &data);
            }
        }
        else
            pcap_rval = pcap_next_ex(context->handle, &pcaphdr, &data);

        if (pcap_rval <= 0)
        {
            if (pcap_rval == 0)
                *rstat = (idx == 0) ? DAQ_RSTAT_TIMEOUT : DAQ_RSTAT_WOULD_BLOCK;
            else if (pcap_rval == -1)
            {
                daq_base_api.instance_set_errbuf(context->instance, "%s", pcap_geterr(context->handle));
                *rstat = DAQ_RSTAT_ERROR;
            }
            else if (context->mode == DAQ_MODE_READ_FILE && pcap_rval == -2)
                *rstat = DAQ_RSTAT_EOF;
            break;
        }

        /* Increment the module instance's packet counter. */
        context->stats.packets_received++;
        /* Update hw packet counters to make sure we detect counter overflow */
        if (++context->hwupdate_count == DAQ_PCAP_ROLLOVER_LIM)
            update_hw_stats(context);

        /* Populate the packet descriptor */
        memcpy(desc->data, data, pcaphdr->caplen);

        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->caplen = pcaphdr->caplen;
        pkthdr->pktlen = pcaphdr->len;
        pkthdr->ts = pcaphdr->ts;
        pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->flags = 0;
        pkthdr->opaque = 0;
        pkthdr->address_space_id = 0;

        msgs[idx] = &desc->msg;

        /* Last, but not least, extract this descriptor from the free list. */
        context->pkt_freelist = desc->next;
        desc->next = NULL;
    }

    return idx;
}

static int pcap_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    Pcap_Context_t *context = (Pcap_Context_t *) handle;
    PcapPktDesc *desc = (PcapPktDesc *) msg->msg;

    /* Sanitize the verdict. */
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    context->stats.verdicts[verdict]++;

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = context->pkt_freelist;
    context->pkt_freelist = desc;

    return DAQ_SUCCESS;
}

static DAQ_PktHdr_t *pcap_daq_packet_header_from_msg(void *handle, const DAQ_Msg_t *msg)
{
    PcapPktDesc *desc;

    if (msg->type != DAQ_MSG_TYPE_PACKET)
        return NULL;
    desc = (PcapPktDesc *) msg->msg;
    return &desc->pkthdr;
}

static const uint8_t *pcap_daq_packet_data_from_msg(void *handle, const DAQ_Msg_t *msg)
{
    PcapPktDesc *desc;

    if (msg->type != DAQ_MSG_TYPE_PACKET)
        return NULL;
    desc = (PcapPktDesc *) msg->msg;
    return desc->data;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t pcap_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_PCAP_VERSION,
    /* .name = */ "pcap",
    /* .type = */ DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .prepare = */ pcap_daq_prepare,
    /* .get_variable_descs = */ pcap_daq_get_variable_descs,
    /* .initialize = */ pcap_daq_initialize,
    /* .set_filter = */ pcap_daq_set_filter,
    /* .start = */ pcap_daq_start,
    /* .inject = */ pcap_daq_inject,
    /* .breakloop = */ pcap_daq_breakloop,
    /* .stop = */ pcap_daq_stop,
    /* .shutdown = */ pcap_daq_shutdown,
    /* .check_status = */ pcap_daq_check_status,
    /* .get_stats = */ pcap_daq_get_stats,
    /* .reset_stats = */ pcap_daq_reset_stats,
    /* .get_snaplen = */ pcap_daq_get_snaplen,
    /* .get_capabilities = */ pcap_daq_get_capabilities,
    /* .get_datalink_type = */ pcap_daq_get_datalink_type,
    /* .get_device_index = */ pcap_daq_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ pcap_daq_msg_receive,
    /* .msg_finalize = */ pcap_daq_msg_finalize,
    /* .packet_header_from_msg = */ pcap_daq_packet_header_from_msg,
    /* .packet_data_from_msg = */ pcap_daq_packet_data_from_msg,
};

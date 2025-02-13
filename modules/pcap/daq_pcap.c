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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "daq_module_api.h"

#define DAQ_PCAP_VERSION 4

#define PCAP_DEFAULT_POOL_SIZE 16
#define DAQ_PCAP_ROLLOVER_LIM 1000000000 //Check for rollover every billionth packet

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

typedef struct _pcap_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    struct _pcap_pkt_desc *next;
} PcapPktDesc;

typedef struct _pcap_msg_pool
{
    PcapPktDesc *pool;
    PcapPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} PcapMsgPool;

typedef struct _pcap_context
{
    /* Configuration */
    char *device;
    char *filter_string;
    unsigned snaplen;
    bool promisc_mode;
    bool immediate_mode;
    int timeout;
    struct timeval timeout_tv;
    int buffer_size;
    DAQ_Mode mode;
    bool readback_timeout;
    /* State */
    DAQ_ModuleInstance_h modinst;
    DAQ_Stats_t stats;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    PcapMsgPool pool;
    pcap_t *handle;
    FILE *fp;
    uint32_t netmask;
    bool nonblocking;
    volatile bool interrupted;
    /* Readback timeout state */
    struct timeval last_recv;
    PcapPktDesc *pending_desc;
    bool final_readback_timeout;
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
    { "readback_timeout", "Return timeout receive status in file readback mode", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

static DAQ_BaseAPI_t daq_base_api;
static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;

static void destroy_packet_pool(Pcap_Context_t *pc)
{
    PcapMsgPool *pool = &pc->pool;
    if (pool->pool)
    {
        while (pool->info.size > 0)
            free(pool->pool[--pool->info.size].data);
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

static int create_packet_pool(Pcap_Context_t *pc, unsigned size)
{
    PcapMsgPool *pool = &pc->pool;
    pool->pool = calloc(sizeof(PcapPktDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(pc->modinst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(PcapPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(PcapPktDesc) * size;
    while (pool->info.size < size)
    {
        /* Allocate packet data and set up descriptor */
        PcapPktDesc *desc = &pool->pool[pool->info.size];
        desc->data = malloc(pc->snaplen);
        if (!desc->data)
        {
            SET_ERROR(pc->modinst, "%s: Could not allocate %d bytes for a packet descriptor message buffer!",
                    __func__, pc->snaplen);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += pc->snaplen;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(desc->pkthdr);
        msg->hdr = &desc->pkthdr;
        msg->data = desc->data;
        msg->owner = pc->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

static int update_hw_stats(Pcap_Context_t *pc)
{
    struct pcap_stat ps;

    if (pc->handle && pc->device)
    {
        memset(&ps, 0, sizeof(struct pcap_stat));
        if (pcap_stats(pc->handle, &ps) == -1)
        {
            SET_ERROR(pc->modinst, "%s", pcap_geterr(pc->handle));
            return DAQ_ERROR;
        }

        /* PCAP receive counter wrapped */
        if (ps.ps_recv < pc->wrap_recv)
            pc->rollover_recv += UINT32_MAX;

        /* PCAP drop counter wrapped */
        if (ps.ps_drop < pc->wrap_drop)
            pc->rollover_drop += UINT32_MAX;

        pc->wrap_recv = ps.ps_recv;
        pc->wrap_drop = ps.ps_drop;

        pc->stats.hw_packets_received = pc->rollover_recv + pc->wrap_recv - pc->base_recv;
        pc->stats.hw_packets_dropped = pc->rollover_drop + pc->wrap_drop - pc->base_drop;
        pc->hwupdate_count = 0;
    }

    return DAQ_SUCCESS;
}

static inline int set_nonblocking(Pcap_Context_t *pc, bool nonblocking)
{
    if (nonblocking != pc->nonblocking)
    {
        int status;
        if ((status = pcap_setnonblock(pc->handle, nonblocking ? 1 : 0, pc->pcap_errbuf)) < 0)
        {
            SET_ERROR(pc->modinst, "%s", pc->pcap_errbuf);
            return status;
        }
        pc->nonblocking = nonblocking;
    }
    return 0;
}

static int pcap_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int pcap_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int pcap_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = pcap_variable_descriptions;

    return sizeof(pcap_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int pcap_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    Pcap_Context_t *pc;

    pc = calloc(1, sizeof(Pcap_Context_t));
    if (!pc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new PCAP context!", __func__);
        return DAQ_ERROR_NOMEM;
    }
    pc->modinst = modinst;

    pc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    pc->timeout = daq_base_api.config_get_timeout(modcfg);
    pc->timeout_tv.tv_sec = pc->timeout / 1000;
    pc->timeout_tv.tv_usec = (pc->timeout % 1000) * 1000;
    pc->promisc_mode = true;
    pc->immediate_mode = true;
    pc->readback_timeout = false;

    const char *varKey, *varValue;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        /* Retrieve the requested buffer size (default = 0) */
        if (!strcmp(varKey, "buffer_size"))
            pc->buffer_size = strtol(varValue, NULL, 10);
        else if (!strcmp(varKey, "no_promiscuous"))
            pc->promisc_mode = false;
        else if (!strcmp(varKey, "no_immediate"))
            pc->immediate_mode = false;
        else if (!strcmp(varKey, "readback_timeout"))
            pc->readback_timeout = true;

        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    int rval = create_packet_pool(pc, pool_size ? pool_size : PCAP_DEFAULT_POOL_SIZE);
    if (rval != DAQ_SUCCESS)
    {
        destroy_packet_pool(pc);
        free(pc);
        return rval;
    }

    pc->mode = daq_base_api.config_get_mode(modcfg);
    if (pc->mode == DAQ_MODE_READ_FILE)
    {
        const char *fname = daq_base_api.config_get_input(modcfg);
        /* Special case: "-" is an alias for stdin */
        if (fname[0] == '-' && fname[1] == '\0')
            pc->fp = stdin;
        else
        {
            pc->fp = fopen(daq_base_api.config_get_input(modcfg), "rb");
            if (!pc->fp)
            {
                SET_ERROR(modinst, "%s: Couldn't open file '%s' for reading: %s", __func__,
                        daq_base_api.config_get_input(modcfg), strerror(errno));
                destroy_packet_pool(pc);
                free(pc);
                return DAQ_ERROR_NOMEM;
            }
        }
    }
    else
    {
        pc->device = strdup(daq_base_api.config_get_input(modcfg));
        if (!pc->device)
        {
            SET_ERROR(modinst, "%s: Couldn't allocate memory for the device string!", __func__);
            destroy_packet_pool(pc);
            free(pc);
            return DAQ_ERROR_NOMEM;
        }
    }

    pc->hwupdate_count = 0;

    *ctxt_ptr = pc;

    return DAQ_SUCCESS;
}

static void pcap_daq_destroy(void *handle)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    if (pc->handle)
        pcap_close(pc->handle);
    if (pc->fp)
        fclose(pc->fp);
    if (pc->device)
        free(pc->device);
    if (pc->filter_string)
        free(pc->filter_string);
    destroy_packet_pool(pc);
    free(pc);
}

static int pcap_daq_install_filter(Pcap_Context_t *pc, const char *filter)
{
    struct bpf_program fcode;

    pthread_mutex_lock(&bpf_mutex);
    if (pcap_compile(pc->handle, &fcode, filter, 1, pc->netmask) < 0)
    {
        pthread_mutex_unlock(&bpf_mutex);
        SET_ERROR(pc->modinst, "%s: pcap_compile: %s", __func__, pcap_geterr(pc->handle));
        return DAQ_ERROR;
    }
    pthread_mutex_unlock(&bpf_mutex);

    if (pcap_setfilter(pc->handle, &fcode) < 0)
    {
        pcap_freecode(&fcode);
        SET_ERROR(pc->modinst, "%s: pcap_setfilter: %s", __func__, pcap_geterr(pc->handle));
        return DAQ_ERROR;
    }

    pcap_freecode(&fcode);

    return DAQ_SUCCESS;
}

static int pcap_daq_set_filter(void *handle, const char *filter)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    if (pc->handle)
    {
        int rval = pcap_daq_install_filter(handle, filter);
        if (rval != DAQ_SUCCESS)
            return rval;
    }
    else
    {
        /* Try to validate the BPF with a dead PCAP handle. */
        pcap_t *dead_handle = pcap_open_dead(DLT_EN10MB, pc->snaplen);
        if (!dead_handle)
        {
            SET_ERROR(pc->modinst, "%s: Could not allocate a dead PCAP handle!", __func__);
            return DAQ_ERROR_NOMEM;
        }
        struct bpf_program fcode;
        pthread_mutex_lock(&bpf_mutex);
        if (pcap_compile(dead_handle, &fcode, filter, 1, pc->netmask) < 0)
        {
            pthread_mutex_unlock(&bpf_mutex);
            SET_ERROR(pc->modinst, "%s: pcap_compile: %s", __func__, pcap_geterr(dead_handle));
            return DAQ_ERROR;
        }
        pthread_mutex_unlock(&bpf_mutex);
        pcap_freecode(&fcode);
        pcap_close(dead_handle);

        /* Store the BPF string for later. */
        if (pc->filter_string)
            free(pc->filter_string);
        pc->filter_string = strdup(filter);
        if (!pc->filter_string)
        {
            SET_ERROR(pc->modinst, "%s: Could not allocate space to store a copy of the filter string!", __func__);
            return DAQ_ERROR_NOMEM;
        }
    }

    return DAQ_SUCCESS;
}

static int pcap_daq_start(void *handle)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;
    uint32_t localnet, netmask;
    uint32_t defaultnet = 0xFFFFFF00;
    int status;

    if (pc->device)
    {
        pc->handle = pcap_create(pc->device, pc->pcap_errbuf);
        if (!pc->handle)
            goto fail;
        if ((status = pcap_set_immediate_mode(pc->handle, pc->immediate_mode ? 1 : 0)) < 0)
            goto fail;
        if ((status = pcap_set_snaplen(pc->handle, pc->snaplen)) < 0)
            goto fail;
        if ((status = pcap_set_promisc(pc->handle, pc->promisc_mode ? 1 : 0)) < 0)
            goto fail;
        if ((status = pcap_set_timeout(pc->handle, pc->timeout)) < 0)
            goto fail;
        if ((status = pcap_set_buffer_size(pc->handle, pc->buffer_size)) < 0)
            goto fail;
        if ((status = pcap_activate(pc->handle)) < 0)
            goto fail;
        if ((status = set_nonblocking(pc, true)) < 0)
            goto fail;
        if (pcap_lookupnet(pc->device, &localnet, &netmask, pc->pcap_errbuf) < 0)
            netmask = htonl(defaultnet);
    }
    else
    {
        pc->handle = pcap_fopen_offline(pc->fp, pc->pcap_errbuf);
        if (!pc->handle)
            goto fail;
        pc->fp = NULL;

        netmask = htonl(defaultnet);
    }
    pc->netmask = netmask;

    if (pc->filter_string)
    {
        if ((status = pcap_daq_install_filter(pc, pc->filter_string)) != DAQ_SUCCESS)
        {
            pcap_close(pc->handle);
            pc->handle = NULL;
            return status;
        }
        free(pc->filter_string);
        pc->filter_string = NULL;
    }

    pcap_daq_reset_stats(handle);

    return DAQ_SUCCESS;

fail:
    if (pc->handle)
    {
        if (status == PCAP_ERROR || status == PCAP_ERROR_NO_SUCH_DEVICE || status == PCAP_ERROR_PERM_DENIED)
            SET_ERROR(pc->modinst, "%s", pcap_geterr(pc->handle));
        else
            SET_ERROR(pc->modinst, "%s: %s", pc->device, pcap_statustostr(status));
        pcap_close(pc->handle);
        pc->handle = NULL;
    }
    else
        SET_ERROR(pc->modinst, "%s", pc->pcap_errbuf);
    return DAQ_ERROR;
}

static int pcap_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    if (type != DAQ_MSG_TYPE_PACKET)
        return DAQ_ERROR_NOTSUP;

    if (pcap_inject(pc->handle, data, data_len) < 0)
    {
        SET_ERROR(pc->modinst, "%s", pcap_geterr(pc->handle));
        return DAQ_ERROR;
    }

    pc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int pcap_daq_interrupt(void *handle)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    pc->interrupted = true;

    return DAQ_SUCCESS;
}

static int pcap_daq_stop(void *handle)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    if (pc->handle)
    {
        /* Store the hardware stats for post-stop stat calls. */
        update_hw_stats(pc);
        pcap_close(pc->handle);
        pc->handle = NULL;
    }

    return DAQ_SUCCESS;
}

static int pcap_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    if (update_hw_stats(pc) != DAQ_SUCCESS)
        return DAQ_ERROR;

    memcpy(stats, &pc->stats, sizeof(DAQ_Stats_t));

    if (pc->mode == DAQ_MODE_READ_FILE)
    {
        stats->hw_packets_received = stats->packets_received + stats->packets_filtered;
    }

    return DAQ_SUCCESS;
}

static void pcap_daq_reset_stats(void *handle)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;
    struct pcap_stat ps;

    memset(&pc->stats, 0, sizeof(DAQ_Stats_t));

    if (!pc->handle)
        return;

    memset(&ps, 0, sizeof(struct pcap_stat));
    if (pc->handle && pc->device && pcap_stats(pc->handle, &ps) == 0)
    {
        pc->base_recv = pc->wrap_recv = ps.ps_recv;
        pc->base_drop = pc->wrap_drop = ps.ps_drop;
    }
}

static int pcap_daq_get_snaplen(void *handle)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    return pc->snaplen;
}

static uint32_t pcap_daq_get_capabilities(void *handle)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;
    uint32_t capabilities = DAQ_CAPA_BPF | DAQ_CAPA_INTERRUPT;

    if (pc->device)
        capabilities |= DAQ_CAPA_INJECT;
    else
        capabilities |= DAQ_CAPA_UNPRIV_START;

    return capabilities;
}

static int pcap_daq_get_datalink_type(void *handle)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    if (pc->handle)
        return pcap_datalink(pc->handle);

    return DLT_NULL;
}

static unsigned pcap_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    struct pcap_pkthdr *pcaphdr;
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;
    const u_char *data;
    unsigned idx;

    *rstat = DAQ_RSTAT_OK;
    for (idx = 0; idx < max_recv; idx++)
    {
        /* Check to see if the receive has been canceled.  If so, reset it and return appropriately. */
        if (pc->interrupted)
        {
            pc->interrupted = false;
            *rstat = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        /* If there is a pending descriptor from the readback timeout feature, check if it's ready
            to be realized.  If it is, finish receiving it and carry on. */
        if (pc->pending_desc)
        {
            struct timeval delta;
            timersub(&pc->pending_desc->pkthdr.ts, &pc->last_recv, &delta);
            if (timercmp(&delta, &pc->timeout_tv, >))
            {
                timeradd(&pc->last_recv, &pc->timeout_tv, &pc->last_recv);
                *rstat = DAQ_RSTAT_TIMEOUT;
                break;
            }
            pc->last_recv = pc->pending_desc->pkthdr.ts;
            pc->pool.info.available--;
            msgs[idx] = &pc->pending_desc->msg;
            pc->stats.packets_received++;
            pc->pending_desc = NULL;
            continue;
        }

        /* Make sure that we have a packet descriptor available to populate *before*
            calling into libpcap. */
        PcapPktDesc *desc = pc->pool.freelist;
        if (!desc)
        {
            *rstat = DAQ_RSTAT_NOBUF;
            break;
        }

        /* When dealing with a live interface, try to get the first packet in non-blocking mode.
            If there's nothing to receive, switch to blocking mode. */
        int pcap_rval;
        if (pc->mode != DAQ_MODE_READ_FILE && idx == 0)
        {
            if (set_nonblocking(pc, true) != DAQ_SUCCESS)
            {
                *rstat = DAQ_RSTAT_ERROR;
                break;
            }
            pcap_rval = pcap_next_ex(pc->handle, &pcaphdr, &data);
            if (pcap_rval == 0)
            {
                if (set_nonblocking(pc, false) != DAQ_SUCCESS)
                {
                    *rstat = DAQ_RSTAT_ERROR;
                    break;
                }
                pcap_rval = pcap_next_ex(pc->handle, &pcaphdr, &data);
            }
        }
        else
            pcap_rval = pcap_next_ex(pc->handle, &pcaphdr, &data);

        if (pcap_rval <= 0)
        {
            if (pcap_rval == 0)
                *rstat = (idx == 0) ? DAQ_RSTAT_TIMEOUT : DAQ_RSTAT_WOULD_BLOCK;
            else if (pcap_rval == -1)
            {
                SET_ERROR(pc->modinst, "%s", pcap_geterr(pc->handle));
                *rstat = DAQ_RSTAT_ERROR;
            }
            else if (pcap_rval == -2)
            {
                /* LibPCAP brilliantly decides to return -2 if it hit EOF in readback OR pcap_breakloop()
                    was called.  Let's try to differentiate by checking to see if we asked for a break. */
                if (!pc->interrupted && pc->mode == DAQ_MODE_READ_FILE)
                {
                    /* Insert a final timeout receive status when readback timeout mode is enabled. */
                    if (pc->readback_timeout && !pc->final_readback_timeout)
                    {
                        pc->final_readback_timeout = true;
                        *rstat = DAQ_RSTAT_TIMEOUT;
                    }
                    else
                        *rstat = DAQ_RSTAT_EOF;
                }
                else
                {
                    pc->interrupted = false;
                    *rstat = DAQ_RSTAT_INTERRUPTED;
                }
            }
            break;
        }

        /* Update hw packet counters to make sure we detect counter overflow */
        if (++pc->hwupdate_count == DAQ_PCAP_ROLLOVER_LIM)
            update_hw_stats(pc);

        /* Populate the packet descriptor */
        int caplen = (pcaphdr->caplen > pc->snaplen) ? pc->snaplen : pcaphdr->caplen;
        memcpy(desc->data, data, caplen);

        /* Next, set up the DAQ message.  Most fields are prepopulated and unchanging. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->data_len = caplen;

        /* Then, set up the DAQ packet header. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->pktlen = pcaphdr->len;
        pkthdr->ts.tv_sec = pcaphdr->ts.tv_sec;
        pkthdr->ts.tv_usec = pcaphdr->ts.tv_usec;

        /* Last, but not least, extract this descriptor from the free list and 
            place the message in the return vector. */
        pc->pool.freelist = desc->next;
        desc->next = NULL;
        /* If the readback timeout feature is enabled, check to see if the configured timeout has
            elapsed between the previous packet and this one.  If it has, store the descriptor for
            later without modifying counters and return the timeout receive status. */
        if (pc->mode == DAQ_MODE_READ_FILE && pc->readback_timeout && pc->timeout > 0)
        {
            if (timerisset(&pc->last_recv) && timercmp(&pkthdr->ts, &pc->last_recv, >))
            {
                struct timeval delta;
                timersub(&pkthdr->ts, &pc->last_recv, &delta);
                if (timercmp(&delta, &pc->timeout_tv, >))
                {
                    pc->pending_desc = desc;
                    timeradd(&pc->last_recv, &pc->timeout_tv, &pc->last_recv);
                    *rstat = DAQ_RSTAT_TIMEOUT;
                    break;
                }
            }
            pc->last_recv = pkthdr->ts;
        }
        pc->pool.info.available--;
        msgs[idx] = &desc->msg;

        /* Finally, increment the module instance's packet counter. */
        pc->stats.packets_received++;
    }

    return idx;
}

static int pcap_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;
    PcapPktDesc *desc = (PcapPktDesc *) msg->priv;

    /* Sanitize the verdict. */
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    pc->stats.verdicts[verdict]++;

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = pc->pool.freelist;
    pc->pool.freelist = desc;
    pc->pool.info.available++;

    return DAQ_SUCCESS;
}

static int pcap_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    Pcap_Context_t *pc = (Pcap_Context_t *) handle;

    *info = pc->pool.info;

    return DAQ_SUCCESS;
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
    /* .load = */ pcap_daq_module_load,
    /* .unload = */ pcap_daq_module_unload,
    /* .get_variable_descs = */ pcap_daq_get_variable_descs,
    /* .instantiate = */ pcap_daq_instantiate,
    /* .destroy = */ pcap_daq_destroy,
    /* .set_filter = */ pcap_daq_set_filter,
    /* .start = */ pcap_daq_start,
    /* .inject = */ pcap_daq_inject,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ pcap_daq_interrupt,
    /* .stop = */ pcap_daq_stop,
    /* .ioctl = */ NULL,
    /* .get_stats = */ pcap_daq_get_stats,
    /* .reset_stats = */ pcap_daq_reset_stats,
    /* .get_snaplen = */ pcap_daq_get_snaplen,
    /* .get_capabilities = */ pcap_daq_get_capabilities,
    /* .get_datalink_type = */ pcap_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ pcap_daq_msg_receive,
    /* .msg_finalize = */ pcap_daq_msg_finalize,
    /* .get_msg_pool_info = */ pcap_daq_get_msg_pool_info,
};

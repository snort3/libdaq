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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "daq_dlt.h"
#include "daq_module_api.h"

#define DAQ_DIVERT_VERSION 1

#define DIVERT_DEFAULT_POOL_SIZE    64

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

typedef struct _divert_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    struct sockaddr_in addr;
    struct _divert_pkt_desc *next;
} DivertPktDesc;

typedef struct _divert_msg_pool
{
    DivertPktDesc *pool;
    DivertPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} DivertMsgPool;

typedef struct _divert_context {
    /* Configuration */
    int port;
    bool passive;
    unsigned timeout;
    unsigned snaplen;
    /* State */
    int sock;
    DAQ_ModuleInstance_h modinst;
    DivertMsgPool pool;
    volatile bool interrupted;
    DAQ_Stats_t stats;
} Divert_Context_t;

static void divert_daq_destroy(void *);

static DAQ_BaseAPI_t daq_base_api;


static void destroy_packet_pool(Divert_Context_t *dc)
{
    DivertMsgPool *pool = &dc->pool;
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

static int create_packet_pool(Divert_Context_t *dc, unsigned size)
{
    DivertMsgPool *pool = &dc->pool;
    pool->pool = calloc(sizeof(DivertPktDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(dc->modinst, "%s: Couldn't allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(DivertPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(DivertPktDesc) * size;
    while (pool->info.size < size)
    {
        /* Allocate packet data and set up descriptor */
        DivertPktDesc *desc = &pool->pool[pool->info.size];
        desc->data = malloc(dc->snaplen);
        if (!desc->data)
        {
            SET_ERROR(dc->modinst, "%s: Couldn't allocate %d bytes for a packet descriptor message buffer!",
                    __func__, dc->snaplen);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += dc->snaplen;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(desc->pkthdr);
        msg->hdr = &desc->pkthdr;
        msg->data = desc->data;
        msg->owner = dc->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

static int divert_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int divert_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int divert_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    Divert_Context_t *dc = calloc(1, sizeof(*dc));

    if (!dc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new Divert context!", __func__);
        return DAQ_ERROR_NOMEM;
    }
    dc->sock = -1;
    dc->modinst = modinst;

    char *endptr;
    errno = 0;
    dc->port = strtoul(daq_base_api.config_get_input(modcfg), &endptr, 10);
    if (*endptr != '\0' || errno != 0 || dc->port > 65535)
    {
        SET_ERROR(modinst, "%s: Invalid divert port number specified: '%s'",
                __func__, daq_base_api.config_get_input(modcfg));
        divert_daq_destroy(dc);
        return DAQ_ERROR_INVAL;
    }

    dc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    dc->timeout = daq_base_api.config_get_timeout(modcfg);
    if (dc->timeout == 0)
        dc->timeout = -1;
    dc->passive = (daq_base_api.config_get_mode(modcfg) == DAQ_MODE_PASSIVE);

    /* Open the divert socket.  Traffic will not start going to it until we bind it in start(). */
    if ((dc->sock = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't open the DIVERT socket: %s", __func__, strerror(errno));
        divert_daq_destroy(dc);
        return DAQ_ERROR;
    }

    /* Finally, create the message buffer pool. */
    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    int rval;
    if ((rval = create_packet_pool(dc, pool_size ? pool_size : DIVERT_DEFAULT_POOL_SIZE)) != DAQ_SUCCESS)
    {
        divert_daq_destroy(dc);
        return rval;
    }

    *ctxt_ptr = dc;

    return DAQ_SUCCESS;
}

static void divert_daq_destroy(void* handle)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;

    if (dc->sock != -1)
        close(dc->sock);
    destroy_packet_pool(dc);
    free(dc);
}

static int divert_daq_start(void *handle)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = PF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(dc->port);

    if (bind(dc->sock, (struct sockaddr *) &sin, sizeof(sin)) == -1)
    {
        SET_ERROR(dc->modinst, "%s: Couldn't bind to port %d on the DIVERT socket: %s",
            __func__, dc->port, strerror(errno));
        return DAQ_ERROR;
    }

    return DAQ_SUCCESS;
}

static int divert_daq_stop(void *handle)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;
    close(dc->sock);
    dc->sock = -1;
    return DAQ_SUCCESS;
}

static int divert_daq_inject_relative(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;
    DivertPktDesc *desc = (DivertPktDesc *) msg->priv;

    /* We don't appear to need to respect the reverse aspect as long as the packet is well-formed enough to be
        routed successfully. */
    ssize_t wrote = sendto(dc->sock, data, data_len, 0, (struct sockaddr*) &desc->addr, sizeof(desc->addr));
    if (wrote < 0 || (unsigned) wrote != data_len)
    {
        SET_ERROR(dc->modinst, "%s: Couldn't send to the DIVERT socket: %s", __func__, strerror(errno));
        return DAQ_ERROR;
    }
    dc->stats.packets_injected++;

    return DAQ_SUCCESS;
}

static unsigned divert_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    struct timeval tv;
    unsigned idx = 0;

    while (idx < max_recv)
    {
        /* Make sure that we have a packet descriptor available to populate. */
        DivertPktDesc *desc = dc->pool.freelist;
        if (!desc)
        {
            status = DAQ_RSTAT_NOBUF;
            break;
        }

        fd_set fdset;

        int rval;
        if (idx == 0)
        {
            int timeout = dc->timeout;
            rval = 0;
            while (timeout != 0 && rval == 0)
            {
                if (dc->interrupted)
                {
                    dc->interrupted = false;
                    *rstat = DAQ_RSTAT_INTERRUPTED;
                    return 0;
                }
                if (timeout >= 1000)
                {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    timeout -= 1000;
                }
                else if (timeout > 0)
                {
                    tv.tv_sec = 0;
                    tv.tv_usec = timeout * 1000;
                    timeout = 0;
                }
                else
                {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                }
                FD_ZERO(&fdset);
                FD_SET(dc->sock, &fdset);
                rval = select(dc->sock + 1, &fdset, NULL, NULL, &tv);
            }
        }
        else
        {
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            FD_ZERO(&fdset);
            FD_SET(dc->sock, &fdset);
            rval = select(dc->sock + 1, &fdset, NULL, NULL, &tv);
        }

        if (rval == -1)
        {
            SET_ERROR(dc->modinst, "%s: Couldn't select on the DIVERT socket: %s", __func__, strerror(errno));
            status = DAQ_RSTAT_ERROR;
            break;
        }

        if (rval == 0)
        {
            status = (idx == 0) ? DAQ_RSTAT_TIMEOUT : DAQ_RSTAT_WOULD_BLOCK;
            break;
        }

        if (FD_ISSET(dc->sock, &fdset))
        {
            socklen_t addrlen = sizeof(desc->addr);
            ssize_t pktlen;

            if ((pktlen = recvfrom(dc->sock, desc->data, dc->snaplen, 0,
                (struct sockaddr *) &desc->addr, &addrlen)) == -1)
            {
                if (errno != EINTR)
                {
                    SET_ERROR(dc->modinst, "%s: Couldn't receive from the DIVERT socket: %s", __func__, strerror(errno));
                    status = DAQ_RSTAT_ERROR;
                    break;
                }
            }

            /*
                On FreeBSD with IPFW divert, the socket address structure returned will look like this:
                    sin_len     = 16    AKA sizeof(struct sockaddr_in)
                    sin_family  = 2     AKA AF_INET
                    sin_port    = <ipfw rule ID>
                    sin_addr    = incoming ? first IP of ingress interface : 0.0.0.0
                    sin_zero[8] = name of interface (up to 8 characters)
            */

            /* Next, set up the DAQ message.  Most fields are prepopulated and unchanging. */
            DAQ_Msg_t *msg = &desc->msg;
            msg->data_len = pktlen;

            /* Then, set up the DAQ packet header. */
            DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
            gettimeofday(&pkthdr->ts, NULL);
            pkthdr->pktlen = pktlen;

            /* Last, but not least, extract this descriptor from the free list and
               place the message in the return vector. */
            dc->pool.freelist = desc->next;
            desc->next = NULL;
            dc->pool.info.available--;
            msgs[idx] = &desc->msg;

            dc->stats.hw_packets_received++;
            dc->stats.packets_received++;

            idx++;
        }
    }

    *rstat = status;

    return idx;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

static int divert_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;
    DivertPktDesc *desc = (DivertPktDesc *) msg->priv;

    /* Sanitize and enact the verdict. */
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_BLOCK;
    dc->stats.verdicts[verdict]++;
    verdict = verdict_translation_table[verdict];
    if (dc->passive || verdict == DAQ_VERDICT_PASS)
    {
        ssize_t wrote = sendto(dc->sock, msg->data, msg->data_len, 0,
                                (struct sockaddr*) &desc->addr, sizeof(desc->addr));
        if (wrote < 0 || (unsigned) wrote != msg->data_len)
        {
            SET_ERROR(dc->modinst, "%s: Couldn't send to the DIVERT socket: %s", __func__, strerror(errno));
            return DAQ_ERROR;
        }
    }

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = dc->pool.freelist;
    dc->pool.freelist = desc;
    dc->pool.info.available++;

    return DAQ_SUCCESS;
}

static int divert_daq_interrupt(void *handle)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;

    dc->interrupted = true;

    return DAQ_SUCCESS;
}

static int divert_daq_get_stats(void *handle, DAQ_Stats_t* stats)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;

    *stats = dc->stats;

    return DAQ_SUCCESS;
}

static void divert_daq_reset_stats(void *handle)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;
    memset(&dc->stats, 0, sizeof(dc->stats));
}

static int divert_daq_get_snaplen(void *handle)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;
    return dc->snaplen;
}

static uint32_t divert_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
        | DAQ_CAPA_INTERRUPT | DAQ_CAPA_UNPRIV_START;
}

static int divert_daq_get_datalink_type(void *handle)
{
    return DLT_RAW;
}

static int divert_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    Divert_Context_t *dc = (Divert_Context_t *) handle;

    *info = dc->pool.info;

    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t divert_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_DIVERT_VERSION,
    /* .name = */ "divert",
    /* .type = */ DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ divert_daq_module_load,
    /* .unload = */ divert_daq_module_unload,
    /* .get_variable_descs = */ NULL,
    /* .instantiate = */ divert_daq_instantiate,
    /* .destroy = */ divert_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ divert_daq_start,
    /* .inject = */ NULL,
    /* .inject_relative = */ divert_daq_inject_relative,
    /* .interrupt = */ divert_daq_interrupt,
    /* .stop = */ divert_daq_stop,
    /* .ioctl = */ NULL,
    /* .get_stats = */ divert_daq_get_stats,
    /* .reset_stats = */ divert_daq_reset_stats,
    /* .get_snaplen = */ divert_daq_get_snaplen,
    /* .get_capabilities = */ divert_daq_get_capabilities,
    /* .get_datalink_type = */ divert_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ divert_daq_msg_receive,
    /* .msg_finalize = */ divert_daq_msg_finalize,
    /* .get_msg_pool_info = */ divert_daq_get_msg_pool_info,
};

/*
** Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "daq_api.h"
#include "daq_dlt.h"

#define DAQ_IPFW_VERSION 4

#define IPFW_DEFAULT_POOL_SIZE  64

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

typedef struct _ipfw_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    struct sockaddr_in addr;
    struct _ipfw_pkt_desc *next;
} IpfwPktDesc;

typedef struct _ipfw_msg_pool
{
    IpfwPktDesc *pool;
    IpfwPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} IpfwMsgPool;

typedef struct _ipfw_context {
    /* Configuration */
    int port;
    bool passive;
    unsigned timeout;
    unsigned snaplen;
    /* State */
    int sock;
    DAQ_ModuleInstance_h modinst;
    IpfwMsgPool pool;
    volatile bool break_loop;
    DAQ_Stats_t stats;
} Ipfw_Context_t;

static void ipfw_daq_destroy(void *);

static DAQ_VariableDesc_t ipfw_variable_descriptions[] = {
};

static DAQ_BaseAPI_t daq_base_api;


static void destroy_packet_pool(Ipfw_Context_t *ipfwc)
{
    IpfwMsgPool *pool = &ipfwc->pool;
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

static int create_packet_pool(Ipfw_Context_t *ipfwc, unsigned size)
{
    IpfwMsgPool *pool = &ipfwc->pool;
    pool->pool = calloc(sizeof(IpfwPktDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(ipfwc->modinst, "%s: Couldn't allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(IpfwPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(IpfwPktDesc) * size;
    while (pool->info.size < size)
    {
        /* Allocate packet data and set up descriptor */
        IpfwPktDesc *desc = &pool->pool[pool->info.size];
        desc->data = malloc(ipfwc->snaplen);
        if (!desc->data)
        {
            SET_ERROR(ipfwc->modinst, "%s: Couldn't allocate %d bytes for a packet descriptor message buffer!",
                    __func__, ipfwc->snaplen);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += ipfwc->snaplen;

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
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

static int ipfw_daq_prepare(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int ipfw_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = ipfw_variable_descriptions;

    return sizeof(ipfw_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int ipfw_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    Ipfw_Context_t *ipfwc = calloc(1, sizeof(*ipfwc));

    if (!ipfwc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new IPFW context!", __func__);
        return DAQ_ERROR_NOMEM;
    }
    ipfwc->sock = -1;
    ipfwc->modinst = modinst;

    char *endptr;
    errno = 0;
    ipfwc->port = strtoul(daq_base_api.config_get_input(modcfg), &endptr, 10);
    if (*endptr != '\0' || errno != 0 || ipfwc->port > 65535)
    {
        SET_ERROR(modinst, "%s: Invalid divert port number specified: '%s'",
                __func__, daq_base_api.config_get_input(modcfg));
        ipfw_daq_destroy(ipfwc);
        return DAQ_ERROR_INVAL;
    }

    ipfwc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    ipfwc->timeout = daq_base_api.config_get_timeout(modcfg);
    if (ipfwc->timeout == 0)
        ipfwc->timeout = -1;
    ipfwc->passive = (daq_base_api.config_get_mode(modcfg) == DAQ_MODE_PASSIVE);

    /* Open the divert socket.  Traffic will not start going to it until we bind it in start(). */
    if ((ipfwc->sock = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't open the DIVERT socket: %s", __func__, strerror(errno));
        ipfw_daq_destroy(ipfwc);
        return DAQ_ERROR;
    }

    /* Finally, create the message buffer pool. */
    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    int rval;
    if ((rval = create_packet_pool(ipfwc, pool_size ? pool_size : IPFW_DEFAULT_POOL_SIZE)) != DAQ_SUCCESS)
    {
        ipfw_daq_destroy(ipfwc);
        return rval;
    }

    *ctxt_ptr = ipfwc;

    return DAQ_SUCCESS;
}

static void ipfw_daq_destroy(void* handle)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;

    if (ipfwc->sock != -1)
        close(ipfwc->sock);
    destroy_packet_pool(ipfwc);
    free(ipfwc);
}

static int ipfw_daq_start(void *handle)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = PF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(ipfwc->port);

    if (bind(ipfwc->sock, (struct sockaddr *) &sin, sizeof(sin)) == -1)
    {
        SET_ERROR(ipfwc->modinst, "%s: Couldn't bind to port %d on the DIVERT socket: %s",
            __func__, ipfwc->port, strerror(errno));
        return DAQ_ERROR;
    }

    return DAQ_SUCCESS;
}

static int ipfw_daq_stop(void *handle)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;
    close(ipfwc->sock);
    ipfwc->sock = -1;
    return DAQ_SUCCESS;
}

static int ipfw_daq_inject(void *handle, const DAQ_Msg_t *msg, const uint8_t *packet_data, uint32_t len, int reverse)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;
    IpfwPktDesc *desc = (IpfwPktDesc *) msg->priv;

    /* We don't appear to need to respect the reverse aspect as long as the packet is well-formed enough to be
        routed successfully. */
    ssize_t wrote = sendto(ipfwc->sock, packet_data, len, 0, (struct sockaddr*) &desc->addr, sizeof(desc->addr));
    if (wrote < 0 || (unsigned) wrote != len)
    {
        SET_ERROR(ipfwc->modinst, "%s: Couldn't send to the DIVERT socket: %s", __func__, strerror(errno));
        return DAQ_ERROR;
    }
    ipfwc->stats.packets_injected++;

    return DAQ_SUCCESS;
}

static unsigned ipfw_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    struct timeval tv;
    unsigned idx = 0;

    while (idx < max_recv)
    {
        /* Make sure that we have a packet descriptor available to populate. */
        IpfwPktDesc *desc = ipfwc->pool.freelist;
        if (!desc)
        {
            status = DAQ_RSTAT_NOBUF;
            break;
        }

        fd_set fdset;

        int rval;
        if (idx == 0)
        {
            int timeout = ipfwc->timeout;
            rval = 0;
            while (timeout != 0 && rval == 0)
            {
                if (ipfwc->break_loop)
                {
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
                FD_SET(ipfwc->sock, &fdset);
                rval = select(ipfwc->sock + 1, &fdset, NULL, NULL, &tv);
            }
        }
        else
        {
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            FD_ZERO(&fdset);
            FD_SET(ipfwc->sock, &fdset);
            rval = select(ipfwc->sock + 1, &fdset, NULL, NULL, &tv);
        }

        if (rval == -1)
        {
            SET_ERROR(ipfwc->modinst, "%s: Couldn't select on the DIVERT socket: %s", __func__, strerror(errno));
            status = DAQ_RSTAT_ERROR;
            break;
        }

        if (rval == 0)
        {
            status = (idx == 0) ? DAQ_RSTAT_TIMEOUT : DAQ_RSTAT_WOULD_BLOCK;
            break;
        }

        if (FD_ISSET(ipfwc->sock, &fdset))
        {
            socklen_t addrlen = sizeof(desc->addr);
            ssize_t pktlen;

            if ((pktlen = recvfrom(ipfwc->sock, desc->data, ipfwc->snaplen, 0,
                (struct sockaddr *) &desc->addr, &addrlen)) == -1)
            {
                if (errno != EINTR)
                {
                    SET_ERROR(ipfwc->modinst, "%s: Couldn't receive from the DIVERT socket: %s", __func__, strerror(errno));
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
                    sin_zero[8] = name of interface (up to 8 characters
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
            ipfwc->pool.freelist = desc->next;
            desc->next = NULL;
            ipfwc->pool.info.available--;
            msgs[idx] = &desc->msg;

            ipfwc->stats.hw_packets_received++;
            ipfwc->stats.packets_received++;

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
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

static int ipfw_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;
    IpfwPktDesc *desc = (IpfwPktDesc *) msg->priv;

    /* Sanitize and enact the verdict. */
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_BLOCK;
    ipfwc->stats.verdicts[verdict]++;
    verdict = verdict_translation_table[verdict];
    if (ipfwc->passive || verdict == DAQ_VERDICT_PASS)
    {
        ssize_t wrote = sendto(ipfwc->sock, msg->data, msg->data_len, 0,
                                (struct sockaddr*) &desc->addr, sizeof(desc->addr));
        if (wrote < 0 || (unsigned) wrote != msg->data_len)
        {
            SET_ERROR(ipfwc->modinst, "%s: Couldn't send to the DIVERT socket: %s", __func__, strerror(errno));
            return DAQ_ERROR;
        }
    }

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = ipfwc->pool.freelist;
    ipfwc->pool.freelist = desc;
    ipfwc->pool.info.available++;

    return DAQ_SUCCESS;
}

static int ipfw_daq_breakloop(void *handle)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;

    ipfwc->break_loop = true;

    return DAQ_SUCCESS;
}

static int ipfw_daq_get_stats(void *handle, DAQ_Stats_t* stats)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;

    *stats = ipfwc->stats;

    return DAQ_SUCCESS;
}

static void ipfw_daq_reset_stats(void *handle)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;
    memset(&ipfwc->stats, 0, sizeof(ipfwc->stats));
}

static int ipfw_daq_get_snaplen(void *handle)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;
    return ipfwc->snaplen;
}

static uint32_t ipfw_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT | DAQ_CAPA_INJECT_RAW
        | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START;
}

static int ipfw_daq_get_datalink_type(void *handle)
{
    return DLT_RAW;
}

static int ipfw_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    Ipfw_Context_t *ipfwc = (Ipfw_Context_t *) handle;

    *info = ipfwc->pool.info;

    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t ipfw_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_IPFW_VERSION,
    /* .name = */ "ipfw",
    /* .type = */ DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .prepare = */ ipfw_daq_prepare,
    /* .get_variable_descs = */ ipfw_daq_get_variable_descs,
    /* .instantiate = */ ipfw_daq_instantiate,
    /* .destroy = */ ipfw_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ ipfw_daq_start,
    /* .inject = */ ipfw_daq_inject,
    /* .breakloop = */ ipfw_daq_breakloop,
    /* .stop = */ ipfw_daq_stop,
    /* .get_stats = */ ipfw_daq_get_stats,
    /* .reset_stats = */ ipfw_daq_reset_stats,
    /* .get_snaplen = */ ipfw_daq_get_snaplen,
    /* .get_capabilities = */ ipfw_daq_get_capabilities,
    /* .get_datalink_type = */ ipfw_daq_get_datalink_type,
    /* .get_device_index = */ NULL,
    /* .modify_flow = */ NULL,
    /* .query_flow = */ NULL,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .msg_receive = */ ipfw_daq_msg_receive,
    /* .msg_finalize = */ ipfw_daq_msg_finalize,
    /* .get_msg_pool_info = */ ipfw_daq_get_msg_pool_info,
};

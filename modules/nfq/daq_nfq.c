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

#include <arpa/inet.h>

#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <libmnl/libmnl.h>

#include "daq_dlt.h"
#include "daq_module_api.h"

/* FIXIT-M Need to figure out how to reimplement inject for NFQ */

#define DAQ_NFQ_VERSION 8

#define NFQ_DEFAULT_POOL_SIZE   16
#define DEFAULT_QUEUE_MAXLEN    1024   // Based on NFQNL_QMAX_DEFAULT from nfnetlnk_queue_core.c

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

typedef struct _nfq_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *nlmsg_buf;
    const struct nlmsghdr *nlmh;
    struct nfqnl_msg_packet_hdr *nlph;
    struct _nfq_pkt_desc *next;
} NfqPktDesc;

typedef struct _nfq_msg_pool
{
    NfqPktDesc *pool;
    NfqPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} NfqMsgPool;

typedef struct _nfq_context
{
    /* Configuration */
    unsigned queue_num;
    int snaplen;
    int timeout;
    unsigned queue_maxlen;
    bool fail_open;
    bool debug;
    /* State */
    DAQ_ModuleInstance_h modinst;
    DAQ_Stats_t stats;
    NfqMsgPool pool;
    char *nlmsg_buf;
    size_t nlmsg_bufsize;
    struct mnl_socket *nlsock;
    int nlsock_fd;
    unsigned portid;
    volatile bool interrupted;
} Nfq_Context_t;

static DAQ_VariableDesc_t nfq_variable_descriptions[] = {
    { "debug", "Enable debugging output to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "fail_open", "Allow the kernel to bypass the netfilter queue when it is full", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "queue_maxlen", "Maximum queue length (default: 1024)", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
};

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_REPLACE,    /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

static DAQ_BaseAPI_t daq_base_api;


/*
 * Private Functions
 */

static void destroy_packet_pool(Nfq_Context_t *nfqc)
{
    NfqMsgPool *pool = &nfqc->pool;
    if (pool->pool)
    {
        while (pool->info.size > 0)
            free(pool->pool[--pool->info.size].nlmsg_buf);
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

static int create_packet_pool(Nfq_Context_t *nfqc, unsigned size)
{
    NfqMsgPool *pool = &nfqc->pool;
    pool->pool = calloc(sizeof(NfqPktDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(nfqc->modinst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(NfqPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(NfqPktDesc) * size;
    while (pool->info.size < size)
    {
        /* Allocate netlink message receive buffer and set up descriptor */
        NfqPktDesc *desc = &pool->pool[pool->info.size];
        desc->nlmsg_buf = malloc(nfqc->nlmsg_bufsize);
        if (!desc->nlmsg_buf)
        {
            SET_ERROR(nfqc->modinst, "%s: Could not allocate %zu bytes for a packet descriptor message buffer!",
                    __func__, nfqc->nlmsg_bufsize);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += nfqc->nlmsg_bufsize;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(desc->pkthdr);
        msg->hdr = &desc->pkthdr;
        msg->owner = nfqc->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = nfqc->pool.freelist;
        nfqc->pool.freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

/* Netlink message building routines vaguely lifted from libmnl's netfilter queue example
    (nf-queue.c) to avoid having to link the seemingly deprecated libnetfilter_queue (which uses
    libmnl anyway). */
static inline struct nlmsghdr *nfq_hdr_put(char *buf, int type, uint32_t queue_num)
{
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(queue_num);

    return nlh;
}

static struct nlmsghdr *nfq_build_cfg_command(char *buf, uint16_t pf, uint8_t command, int queue_num)
{
    struct nlmsghdr *nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
    struct nfqnl_msg_config_cmd cmd = {
        .command = command,
        .pf = htons(pf),
    };
    mnl_attr_put(nlh, NFQA_CFG_CMD, sizeof(cmd), &cmd);

    return nlh;
}

static struct nlmsghdr *nfq_build_cfg_params(char *buf, uint8_t mode, int range, int queue_num)
{
    struct nlmsghdr *nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
    struct nfqnl_msg_config_params params = {
        .copy_range = htonl(range),
        .copy_mode = mode,
    };
    mnl_attr_put(nlh, NFQA_CFG_PARAMS, sizeof(params), &params);

    return nlh;
}

static struct nlmsghdr *nfq_build_verdict(char *buf, int id, int queue_num, int verd, uint32_t plen, uint8_t *pkt)
{
    struct nlmsghdr *nlh = nfq_hdr_put(buf, NFQNL_MSG_VERDICT, queue_num);
    struct nfqnl_msg_verdict_hdr vh = {
        .verdict = htonl(verd),
        .id = htonl(id),
    };
    mnl_attr_put(nlh, NFQA_VERDICT_HDR, sizeof(vh), &vh);
    if (plen)
        mnl_attr_put(nlh, NFQA_PAYLOAD, plen, pkt);

    return nlh;
}

/* Oh, don't mind me; I'm just reimplementing all of mnl_socket_recvfrom so that I can pass in
    a single flag to recvmsg (MSG_DONTWAIT). */
static ssize_t nl_socket_recv(const Nfq_Context_t *nfqc, void *buf, size_t bufsiz, bool blocking)
{
    ssize_t ret;
    struct sockaddr_nl addr;
    struct iovec iov = {
        .iov_base   = buf,
        .iov_len    = bufsiz,
    };
    struct msghdr msg = {
        .msg_name   = &addr,
        .msg_namelen    = sizeof(struct sockaddr_nl),
        .msg_iov    = &iov,
        .msg_iovlen = 1,
        .msg_control    = NULL,
        .msg_controllen = 0,
        .msg_flags  = 0,
    };
    ret = recvmsg(nfqc->nlsock_fd, &msg, blocking ? 0 : MSG_DONTWAIT);
    if (ret == -1)
        return ret;

    if (msg.msg_flags & MSG_TRUNC) {
        errno = ENOSPC;
        return -1;
    }
    if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
        errno = EINVAL;
        return -1;
    }
    return ret;
}

static int parse_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    /* skip unsupported attribute in user-space */
    if (mnl_attr_type_valid(attr, NFQA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
        case NFQA_MARK:
        case NFQA_IFINDEX_INDEV:
        case NFQA_IFINDEX_OUTDEV:
        case NFQA_IFINDEX_PHYSINDEV:
        case NFQA_IFINDEX_PHYSOUTDEV:
        case NFQA_CAP_LEN:
        case NFQA_SKB_INFO:
        case NFQA_SECCTX:
        case NFQA_UID:
        case NFQA_GID:
        case NFQA_CT_INFO:
            if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
                return MNL_CB_ERROR;
            break;
        case NFQA_TIMESTAMP:
            if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
                        sizeof(struct nfqnl_msg_packet_timestamp)) < 0) {
                return MNL_CB_ERROR;
            }
            break;
        case NFQA_HWADDR:
            if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
                        sizeof(struct nfqnl_msg_packet_hw)) < 0) {
                return MNL_CB_ERROR;
            }
            break;
        case NFQA_PACKET_HDR:
            if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
                        sizeof(struct nfqnl_msg_packet_hdr)) < 0) {
                return MNL_CB_ERROR;
            }
            break;
        case NFQA_PAYLOAD:
        case NFQA_CT:
        case NFQA_EXP:
            break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static int process_message_cb(const struct nlmsghdr *nlh, void *data)
{
    NfqPktDesc *desc = (NfqPktDesc *) data;
    struct nlattr *attr[NFQA_MAX+1] = { };
    int ret;

    /* FIXIT-L In the event that there is actually more than one packet per message, handle it gracefully.
        I haven't actually seen this happen yet. */
    if (desc->nlmh)
        return MNL_CB_ERROR;

    /* Parse the message attributes */
    if ((ret = mnl_attr_parse(nlh, sizeof(struct nfgenmsg), parse_attr_cb, attr)) != MNL_CB_OK)
        return ret;

    /* Populate the packet descriptor */
    desc->nlmh = nlh;
    desc->nlph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    /* Set up the DAQ message and packet headers.  Most fields are prepopulated and unchanging. */
    DAQ_Msg_t *msg = &desc->msg;
    msg->data = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

    DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
    pkthdr->pktlen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    if (attr[NFQA_CAP_LEN])
        msg->data_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
    else
        msg->data_len = pkthdr->pktlen;
    /*
     * FIXIT-M Implement getting timestamps from the message if it happens to have that attribute
    if (attr[NFQA_TIMESTAMP])
    {
        struct nfqnl_msg_packet_timestamp *qpt = (struct nfqnl_msg_packet_timestamp *) mnl_attr_get_payload(attr[NFQA_TIMESTAMP]);
        ...
    }
    else
    */
        gettimeofday(&pkthdr->ts, NULL);
    if (attr[NFQA_IFINDEX_INDEV])
        pkthdr->ingress_index = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_INDEV]));
    else
        pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
    if (attr[NFQA_IFINDEX_OUTDEV])
        pkthdr->egress_index = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_OUTDEV]));
    else
        pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;

    return MNL_CB_OK;
}


/*
 * DAQ Module API Implementation
 */

/* Module->load() */
static int nfq_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

/* Module->unload() */
static int nfq_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

/* Module->get_variable_descs() */
static int nfq_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = nfq_variable_descriptions;

    return sizeof(nfq_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

/* Module->instantiate() */
static int nfq_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    Nfq_Context_t *nfqc;
    int rval = DAQ_ERROR;

    nfqc = calloc(1, sizeof(Nfq_Context_t));
    if (!nfqc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new NFQ context", __func__);
        return DAQ_ERROR_NOMEM;
    }
    nfqc->modinst = modinst;

    nfqc->queue_maxlen = DEFAULT_QUEUE_MAXLEN;

    char *endptr;
    errno = 0;
    nfqc->queue_num = strtoul(daq_base_api.config_get_input(modcfg), &endptr, 10);
    if (*endptr != '\0' || errno != 0)
    {
        SET_ERROR(modinst, "%s: Invalid queue number specified: '%s'",
                __func__, daq_base_api.config_get_input(modcfg));
        rval = DAQ_ERROR_INVAL;
        goto fail;
    }

    const char *varKey, *varValue;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "debug"))
            nfqc->debug = true;
        else if (!strcmp(varKey, "fail_open"))
            nfqc->fail_open = true;
        else if (!strcmp(varKey, "queue_maxlen"))
        {
            errno = 0;
            nfqc->queue_maxlen = strtol(varValue, NULL, 10);
            if (*endptr != '\0' || errno != 0)
            {
                SET_ERROR(modinst, "%s: Invalid value for key '%s': '%s'",
                        __func__, varKey, varValue);
                rval = DAQ_ERROR_INVAL;
                goto fail;
            }
        }

        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    nfqc->snaplen = daq_base_api.config_get_snaplen(modcfg);

    /* Largest desired packet payload plus netlink data overhead - this is probably overkill
        (the libnetfilter_queue example inexplicably halves MNL_SOCKET_BUFFER_SIZE), but it
        should be safe from truncation.  */
    nfqc->nlmsg_bufsize = nfqc->snaplen + MNL_SOCKET_BUFFER_SIZE;
    if (nfqc->debug)
        printf("Netlink message buffer size is %zu\n", nfqc->nlmsg_bufsize);

    /* Allocate a scratch buffer for general usage by the context (basically for anything that's not
        receiving a packet) */
    nfqc->nlmsg_buf = malloc(nfqc->nlmsg_bufsize);
    if (!nfqc->nlmsg_buf)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate %zu bytes for a general use buffer",
                __func__, nfqc->nlmsg_bufsize);
        rval = DAQ_ERROR_NOMEM;
        goto fail;
    }

    /* Netlink message buffer length must be determined prior to creating packet pool */
    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    if ((rval = create_packet_pool(nfqc, pool_size ? pool_size : NFQ_DEFAULT_POOL_SIZE)) != DAQ_SUCCESS)
        goto fail;

    /* Open the netfilter netlink socket */
    nfqc->nlsock = mnl_socket_open(NETLINK_NETFILTER);
    if (!nfqc->nlsock)
    {
        SET_ERROR(modinst, "%s: Couldn't open netfilter netlink socket: %s (%d)",
                __func__, strerror(errno), errno);
        goto fail;
    }
    /* Cache the socket file descriptor for later use in the critical path for receive */
    nfqc->nlsock_fd = mnl_socket_get_fd(nfqc->nlsock);

    /* Implement the requested timeout by way of the receive timeout on the netlink socket */
    nfqc->timeout = daq_base_api.config_get_timeout(modcfg);
    if (nfqc->timeout)
    {
        struct timeval tv;
        tv.tv_sec = nfqc->timeout / 1000;
        tv.tv_usec = (nfqc->timeout % 1000) * 1000;
        if (setsockopt(nfqc->nlsock_fd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv)) == -1)
        {
            SET_ERROR(modinst, "%s: Couldn't set receive timeout on netlink socket: %s (%d)",
                    __func__, strerror(errno), errno);
            goto fail;
        }
    }

    /* Set the socket receive buffer to something reasonable based on the desired queue and capture lengths.
        Try with FORCE first to allow overriding the system's global rmem_max, then fall back on being limited
        by it if that doesn't work.
        The value will be doubled to allow room for bookkeeping overhead, so the default of 1024 * 1500 will
        end up allocating about 3MB of receive buffer space.  The unmodified default tends to be around 208KB. */
    unsigned int socket_rcvbuf_size = nfqc->queue_maxlen * nfqc->snaplen;
    if (setsockopt(nfqc->nlsock_fd, SOL_SOCKET, SO_RCVBUFFORCE, &socket_rcvbuf_size, sizeof(socket_rcvbuf_size)) == -1)
    {
        if (setsockopt(nfqc->nlsock_fd, SOL_SOCKET, SO_RCVBUF, &socket_rcvbuf_size, sizeof(socket_rcvbuf_size)) == -1)
        {
            SET_ERROR(modinst, "%s: Couldn't set receive buffer size on netlink socket to %u: %s (%d)",
                    __func__, socket_rcvbuf_size, strerror(errno), errno);
            goto fail;
        }
    }
    if (nfqc->debug)
        printf("Set socket receive buffer size to %u\n", socket_rcvbuf_size);

    if (mnl_socket_bind(nfqc->nlsock, 0, MNL_SOCKET_AUTOPID) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't bind the netlink socket: %s (%d)",
                __func__, strerror(errno), errno);
        goto fail;
    }
    nfqc->portid = mnl_socket_get_portid(nfqc->nlsock);

    struct nlmsghdr *nlh;

    /* The following four packet family unbind/bind commands do nothing on modern (3.8+) kernels.
        They used to handle binding the netfilter socket to a particular address family. */
    nlh = nfq_build_cfg_command(nfqc->nlmsg_buf, AF_INET, NFQNL_CFG_CMD_PF_UNBIND, 0);
    if (mnl_socket_sendto(nfqc->nlsock, nlh, nlh->nlmsg_len) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't unbind from NFQ for AF_INET: %s (%d)",
                __func__, strerror(errno), errno);
        goto fail;
    }
    nlh = nfq_build_cfg_command(nfqc->nlmsg_buf, AF_INET6, NFQNL_CFG_CMD_PF_UNBIND, 0);
    if (mnl_socket_sendto(nfqc->nlsock, nlh, nlh->nlmsg_len) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't unbind from NFQ for AF_INET6: %s (%d)",
                __func__, strerror(errno), errno);
        goto fail;
    }
    nlh = nfq_build_cfg_command(nfqc->nlmsg_buf, AF_INET, NFQNL_CFG_CMD_PF_BIND, 0);
    if (mnl_socket_sendto(nfqc->nlsock, nlh, nlh->nlmsg_len) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't bind to NFQ for AF_INET: %s (%d)",
                __func__, strerror(errno), errno);
        goto fail;
    }
    nlh = nfq_build_cfg_command(nfqc->nlmsg_buf, AF_INET6, NFQNL_CFG_CMD_PF_BIND, 0);
    if (mnl_socket_sendto(nfqc->nlsock, nlh, nlh->nlmsg_len) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't bind to NFQ for AF_INET6: %s (%d)",
                __func__, strerror(errno), errno);
        goto fail;
    }

    /* Now, actually bind to the netfilter queue.  The address family specified is irrelevant. */
    nlh = nfq_build_cfg_command(nfqc->nlmsg_buf, AF_UNSPEC, NFQNL_CFG_CMD_BIND, nfqc->queue_num);
    if (mnl_socket_sendto(nfqc->nlsock, nlh, nlh->nlmsg_len) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't bind to NFQ queue %u: %s (%d)",
                __func__, nfqc->queue_num, strerror(errno), errno);
        goto fail;
    }

    /*
     * Set the queue into packet copying mode with a max copying length of our snaplen.
     * While we're building a configuration message, we might as well tack on our requested
     * maximum queue length and enable delivery of packets that will be subject to GSO. That
     * last bit means we'll potentially see packets larger than the device MTU prior to their
     * trip through the segmentation offload path.  They'll probably show up as truncated.
     */
    nlh = nfq_build_cfg_params(nfqc->nlmsg_buf, NFQNL_COPY_PACKET, nfqc->snaplen, nfqc->queue_num);
    mnl_attr_put_u32(nlh, NFQA_CFG_QUEUE_MAXLEN, htonl(nfqc->queue_maxlen));
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));
    if (nfqc->fail_open)
    {
        mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_FAIL_OPEN));
        mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_FAIL_OPEN));
    }
    if (mnl_socket_sendto(nfqc->nlsock, nlh, nlh->nlmsg_len) == -1)
    {
        SET_ERROR(modinst, "%s: Couldn't configure NFQ parameters: %s (%d)",
                __func__, strerror(errno), errno);
        goto fail;
    }

    *ctxt_ptr = nfqc;

    return DAQ_SUCCESS;

fail:
    if (nfqc)
    {
        if (nfqc->nlsock)
            mnl_socket_close(nfqc->nlsock);
        if (nfqc->nlmsg_buf)
            free(nfqc->nlmsg_buf);
        destroy_packet_pool(nfqc);
        free(nfqc);
    }

    return rval;
}

/* Module->destroy() */
static void nfq_daq_destroy(void *handle)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;

    if (nfqc->nlsock)
        mnl_socket_close(nfqc->nlsock);
    if (nfqc->nlmsg_buf)
        free(nfqc->nlmsg_buf);
    destroy_packet_pool(nfqc);
    free(nfqc);
}

/* Module->start() */
static int nfq_daq_start(void *handle)
{
    return DAQ_SUCCESS;
}

/* Module->interrupt() */
static int nfq_daq_interrupt(void *handle)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;

    nfqc->interrupted = true;

    return DAQ_SUCCESS;
}

/* Module->stop() */
static int nfq_daq_stop(void *handle)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;

    struct nlmsghdr *nlh = nfq_build_cfg_command(nfqc->nlmsg_buf, AF_INET, NFQNL_CFG_CMD_UNBIND, nfqc->queue_num);
    if (mnl_socket_sendto(nfqc->nlsock, nlh, nlh->nlmsg_len) == -1)
    {
        SET_ERROR(nfqc->modinst, "%s: Couldn't bind to NFQ queue %u: %s (%d)",
                __func__, nfqc->queue_num, strerror(errno), errno);
        return DAQ_ERROR;
    }
    mnl_socket_close(nfqc->nlsock);
    nfqc->nlsock = NULL;

    return DAQ_SUCCESS;
}

/* Module->get_stats() */
static int nfq_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;

    /* There is no distinction between packets received by the hardware and those we saw. */
    nfqc->stats.hw_packets_received = nfqc->stats.packets_received;

    memcpy(stats, &nfqc->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

/* Module->reset_stats() */
static void nfq_daq_reset_stats(void *handle)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;

    memset(&nfqc->stats, 0, sizeof(DAQ_Stats_t));
}

/* Module->get_snaplen() */
static int nfq_daq_get_snaplen(void *handle)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;

    return nfqc->snaplen;
}

/* Module->get_capabilities() */
static uint32_t nfq_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INTERRUPT;
}

/* Module->get_datalink_type() */
static int nfq_daq_get_datalink_type(void *handle)
{
    return DLT_RAW;
}

/* Module->msg_receive() */
static unsigned nfq_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;
    unsigned idx = 0;

    *rstat = DAQ_RSTAT_OK;
    while (idx < max_recv)
    {
        /* If the receive has been canceled, break out of the loop and return. */
        if (nfqc->interrupted)
        {
            nfqc->interrupted = false;
            *rstat = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        /* Make sure that we have a packet descriptor available to populate. */
        NfqPktDesc *desc = nfqc->pool.freelist;
        if (!desc)
        {
            *rstat = DAQ_RSTAT_NOBUF;
            break;
        }

        ssize_t ret = nl_socket_recv(nfqc, desc->nlmsg_buf, nfqc->nlmsg_bufsize, idx == 0);
        if (ret < 0)
        {
            if (errno == ENOBUFS)
            {
                nfqc->stats.hw_packets_dropped++;
                continue;
            }
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                *rstat = (idx == 0) ? DAQ_RSTAT_TIMEOUT : DAQ_RSTAT_WOULD_BLOCK;
            else if (errno == EINTR)
            {
                if (!nfqc->interrupted)
                    continue;
                nfqc->interrupted = false;
                *rstat = DAQ_RSTAT_INTERRUPTED;
            }
            else
            {
                SET_ERROR(nfqc->modinst, "%s: Socket receive failed: %zd - %s (%d)",
                        __func__, ret, strerror(errno), errno);
                *rstat = DAQ_RSTAT_ERROR;
            }
            break;
        }
        errno = 0;
        ret = mnl_cb_run(desc->nlmsg_buf, ret, 0, nfqc->portid, process_message_cb, desc);
        if (ret < 0)
        {
            SET_ERROR(nfqc->modinst, "%s: Netlink message processing failed: %zd - %s (%d)",
                    __func__, ret, strerror(errno), errno);
            *rstat = DAQ_RSTAT_ERROR;
            break;
        }

        /* Increment the module instance's packet counter. */
        nfqc->stats.packets_received++;

        /* Last, but not least, extract this descriptor from the free list and
            place the message in the return vector. */
        nfqc->pool.freelist = desc->next;
        desc->next = NULL;
        nfqc->pool.info.available--;
        msgs[idx] = &desc->msg;

        idx++;
    }

    return idx;
}

/* Module->msg_finalize() */
static int nfq_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;
    NfqPktDesc *desc = (NfqPktDesc *) msg->priv;

    /* Sanitize the verdict. */
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    nfqc->stats.verdicts[verdict]++;
    verdict = verdict_translation_table[verdict];

    /* Send the verdict back to the kernel through netlink */
    /* FIXIT-L Consider using an iovec for scatter/gather transmission with the new payload as a
        separate entry. This would avoid a copy and potentially avoid buffer size restrictions.
        Only as relevant as REPLACE is common. */
    uint32_t plen = (verdict == DAQ_VERDICT_REPLACE) ? msg->data_len : 0;
    int nfq_verdict = (verdict == DAQ_VERDICT_PASS || verdict == DAQ_VERDICT_REPLACE) ? NF_ACCEPT : NF_DROP;;
    struct nlmsghdr *nlh = nfq_build_verdict(nfqc->nlmsg_buf, ntohl(desc->nlph->packet_id), nfqc->queue_num,
            nfq_verdict, plen, msg->data);
    if (mnl_socket_sendto(nfqc->nlsock, nlh, nlh->nlmsg_len) == -1)
    {
        SET_ERROR(nfqc->modinst, "%s: Couldn't send NFQ verdict: %s (%d)",
                        __func__, strerror(errno), errno);
        return DAQ_ERROR;
    }

    /* Toss the descriptor back on the free list for reuse.
        Make sure to clear out the netlink message header to show that it is unused. */
    desc->nlmh = NULL;
    desc->next = nfqc->pool.freelist;
    nfqc->pool.freelist = desc;
    nfqc->pool.info.available++;

    return DAQ_SUCCESS;
}

static int nfq_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    Nfq_Context_t *nfqc = (Nfq_Context_t *) handle;

    *info = nfqc->pool.info;

    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t nfq_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_NFQ_VERSION,
    /* .name = */ "nfq",
    /* .type = */ DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE | DAQ_TYPE_NO_UNPRIV,
    /* .load = */ nfq_daq_module_load,
    /* .unload = */ nfq_daq_module_unload,
    /* .get_variable_descs = */ nfq_daq_get_variable_descs,
    /* .instantiate = */ nfq_daq_instantiate,
    /* .destroy = */ nfq_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ nfq_daq_start,
    /* .inject = */ NULL,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ nfq_daq_interrupt,
    /* .stop = */ nfq_daq_stop,
    /* .ioctl = */ NULL,
    /* .get_stats = */ nfq_daq_get_stats,
    /* .reset_stats = */ nfq_daq_reset_stats,
    /* .get_snaplen = */ nfq_daq_get_snaplen,
    /* .get_capabilities = */ nfq_daq_get_capabilities,
    /* .get_datalink_type = */ nfq_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ nfq_daq_msg_receive,
    /* .msg_finalize = */ nfq_daq_msg_finalize,
    /* .get_msg_pool_info = */ nfq_daq_get_msg_pool_info,
};

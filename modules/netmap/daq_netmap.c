/*
** Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <poll.h>
#include <stdbool.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "daq_dlt.h"
#include "daq_module_api.h"

#define DAQ_NETMAP_VERSION      3

/* Hi! I'm completely arbitrary! */
#define NETMAP_MAX_INTERFACES       32

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

typedef struct _netmap_instance
{
    struct _netmap_instance *next;
    struct _netmap_instance *peer;
    int fd;
    int index;
    struct netmap_if *nifp;
    /* TX ring info */
    uint16_t first_tx_ring;
    uint16_t last_tx_ring;
    uint16_t cur_tx_ring;
    /* RX ring info */
    uint16_t first_rx_ring;
    uint16_t last_rx_ring;
    uint16_t cur_rx_ring;
    /* MMAP'd memory */
    void *mem;
    uint32_t memsize;
    struct nmreq req;
    unsigned long long tx_discards;
} NetmapInstance;

typedef struct _netmap_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    NetmapInstance *instance;
    unsigned int length;
    struct _netmap_pkt_desc *next;
} NetmapPktDesc;

typedef struct
{
    NetmapPktDesc *pool;
    NetmapPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} NetmapMsgPool;

typedef struct _netmap_context
{
    /* Configuration */
    char *device;
    int snaplen;
    int timeout;
    bool debug;
    /* State */
    DAQ_ModuleInstance_h modinst;
    NetmapMsgPool pool;
    NetmapInstance *instances;
    uint32_t intf_count;
    volatile bool interrupted;
    DAQ_Stats_t stats;
    /* Message receive state */
    NetmapInstance *curr_instance;
} Netmap_Context_t;

static DAQ_VariableDesc_t netmap_variable_descriptions[] = {
    { "debug", "Enable debugging output to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

static DAQ_BaseAPI_t daq_base_api;

static inline void nminst_inc_rx_ring(NetmapInstance *instance)
{
    instance->cur_rx_ring++;
    if (instance->cur_rx_ring > instance->last_rx_ring)
        instance->cur_rx_ring = instance->first_rx_ring;
}

static inline void nminst_inc_tx_ring(NetmapInstance *instance)
{
    instance->cur_tx_ring++;
    if (instance->cur_tx_ring > instance->last_tx_ring)
        instance->cur_tx_ring = instance->first_tx_ring;
}

static void destroy_packet_pool(Netmap_Context_t *nmc)
{
    NetmapMsgPool *pool = &nmc->pool;
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

static int create_packet_pool(Netmap_Context_t *nmc, unsigned size)
{
    NetmapMsgPool *pool = &nmc->pool;
    pool->pool = calloc(sizeof(NetmapPktDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(nmc->modinst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(NetmapPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(NetmapPktDesc) * size;
    while (pool->info.size < size)
    {
        /* Allocate packet data and set up descriptor */
        NetmapPktDesc *desc = &pool->pool[pool->info.size];
        desc->data = malloc(nmc->snaplen);
        if (!desc->data)
        {
            SET_ERROR(nmc->modinst, "%s: Could not allocate %d bytes for a packet descriptor message buffer!",
                    __func__, nmc->snaplen);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += nmc->snaplen;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(desc->pkthdr);
        msg->hdr = &desc->pkthdr;
        msg->data = desc->data;
        msg->owner = nmc->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

static void destroy_instance(NetmapInstance *instance)
{
    if (instance)
    {
        /* Unmap the packet memory region.  If we had a peer, notify them that
            the shared mapping has been freed and that we no longer exist. */
        if (instance->mem)
        {
            munmap(instance->mem, instance->memsize);
            if (instance->peer)
            {
                instance->peer->mem = MAP_FAILED;
                instance->peer->memsize = 0;
            }
        }
        if (instance->peer)
            instance->peer->peer = NULL;
        if (instance->fd != -1)
            close(instance->fd);
        free(instance);
    }
}

static int netmap_close(Netmap_Context_t *nmc)
{
    NetmapInstance *instance;

    if (!nmc)
        return -1;

    /* Free all of the device instances. */
    while ((instance = nmc->instances) != NULL)
    {
        nmc->instances = instance->next;
        if (nmc->debug)
        {
            printf("Netmap instance %s (%d) discarded %llu TX packets.\n",
                    instance->req.nr_name, instance->index, instance->tx_discards);
        }
        destroy_instance(instance);
    }

    return 0;
}

static NetmapInstance *create_instance(const char *device, NetmapInstance *parent, DAQ_ModuleInstance_h modinst)
{
    NetmapInstance *instance;
    struct nmreq *req;
    static int index = 0;

    instance = calloc(1, sizeof(NetmapInstance));
    if (!instance)
    {
        SET_ERROR(modinst, "%s: Could not allocate a new instance structure.", __func__);
        goto err;
    }

    /* Initialize the instance, including an arbitrary and unique device index. */
    instance->mem = MAP_FAILED;
    instance->index = index;
    index++;

    /* Open /dev/netmap for communications to the driver. */
    instance->fd = open("/dev/netmap", O_RDWR);
    if (instance->fd < 0)
    {
        SET_ERROR(modinst, "%s: Could not open /dev/netmap: %s (%d)",
                    __func__, strerror(errno), errno);
        goto err;
    }

    /* Initialize the netmap request object. */
    req = &instance->req;
    strncpy(req->nr_name, device, sizeof(req->nr_name));
    req->nr_version = NETMAP_API;
    req->nr_ringid = 0;
    req->nr_flags = NR_REG_ALL_NIC;

    return instance;

err:
    destroy_instance(instance);
    return NULL;
}

static int create_bridge(Netmap_Context_t *nmc, const char *device_name1, const char *device_name2)
{
    NetmapInstance *instance, *peer1, *peer2;

    peer1 = peer2 = NULL;
    for (instance = nmc->instances; instance; instance = instance->next)
    {
        if (!strcmp(instance->req.nr_name, device_name1))
            peer1 = instance;
        else if (!strcmp(instance->req.nr_name, device_name2))
            peer2 = instance;
    }

    if (!peer1 || !peer2)
        return DAQ_ERROR_NODEV;

    peer1->peer = peer2;
    peer2->peer = peer1;

    return DAQ_SUCCESS;
}

static int start_instance(Netmap_Context_t *nmc, NetmapInstance *instance)
{
    if (ioctl(instance->fd, NIOCREGIF, &instance->req))
    {
        SET_ERROR(nmc->modinst, "%s: Netmap registration for %s failed: %s (%d)",
                __func__, instance->req.nr_name, strerror(errno), errno);
        return DAQ_ERROR;
    }

    /* Only mmap the packet memory region for the first interface in a pair. */
    if (instance->peer && instance->peer->mem != MAP_FAILED)
    {
        instance->memsize = instance->peer->memsize;
        instance->mem = instance->peer->mem;
    }
    else
    {
        instance->memsize = instance->req.nr_memsize;
        instance->mem = mmap(0, instance->memsize, PROT_WRITE | PROT_READ, MAP_SHARED, instance->fd, 0);
        if (instance->mem == MAP_FAILED)
        {
            SET_ERROR(nmc->modinst, "%s: Could not MMAP the buffer memory region for %s: %s (%d)",
                    __func__, instance->req.nr_name, strerror(errno), errno);
            return DAQ_ERROR;
        }
    }

    instance->nifp = NETMAP_IF(instance->mem, instance->req.nr_offset);

    instance->first_tx_ring = 0;
    instance->first_rx_ring = 0;
    instance->last_tx_ring = instance->req.nr_tx_rings - 1;
    instance->last_rx_ring = instance->req.nr_rx_rings - 1;

    if (nmc->debug)
    {
        struct netmap_ring *ring;
        int i;

        printf("[%s]\n", instance->req.nr_name);
        printf("  nr_tx_slots: %u\n", instance->req.nr_tx_slots);
        printf("  nr_rx_slots: %u\n", instance->req.nr_rx_slots);
        printf("  nr_tx_rings: %hu\n", instance->req.nr_tx_rings);
        for (i = instance->first_tx_ring; i <= instance->last_tx_ring; i++)
        {
            ring = NETMAP_TXRING(instance->nifp, i);
            printf("  [TX Ring %d]\n", i);
            printf("    buf_ofs = %zu\n", ring->buf_ofs);
            printf("    num_slots = %u\n", ring->num_slots);
            printf("    nr_buf_size = %u\n", ring->nr_buf_size);
            printf("    flags = 0x%x\n", ring->flags);
        }
        printf("  nr_rx_rings: %hu\n", instance->req.nr_rx_rings);
        for (i = instance->first_rx_ring; i <= instance->last_rx_ring; i++)
        {
            ring = NETMAP_RXRING(instance->nifp, i);
            printf("  [RX Ring %d]\n", i);
            printf("    buf_ofs = %zu\n", ring->buf_ofs);
            printf("    num_slots = %u\n", ring->num_slots);
            printf("    nr_buf_size = %u\n", ring->nr_buf_size);
            printf("    flags = 0x%x\n", ring->flags);
        }
        printf("  memsize:     %u\n", instance->memsize);
        printf("  index:       %d\n", instance->index);
    }

    return DAQ_SUCCESS;
}

static int netmap_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int netmap_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int netmap_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = netmap_variable_descriptions;

    return sizeof(netmap_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int netmap_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    Netmap_Context_t *nmc;
    char intf[IFNAMSIZ];
    size_t len;
    uint32_t num_intfs = 0;
    int rval = DAQ_ERROR;

    nmc = calloc(1, sizeof(Netmap_Context_t));
    if (!nmc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new Netmap context!", __func__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }
    nmc->modinst = modinst;

    nmc->device = strdup(daq_base_api.config_get_input(modcfg));
    if (!nmc->device)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the device string!", __func__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    nmc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    nmc->timeout = (daq_base_api.config_get_timeout(modcfg) > 0) ? (int) daq_base_api.config_get_timeout(modcfg) : -1;

    DAQ_Mode mode = daq_base_api.config_get_mode(modcfg);
    char *dev = nmc->device;
    if (*dev == ':' || ((len = strlen(dev)) > 0 && *(dev + len - 1) == ':') || 
            (mode == DAQ_MODE_PASSIVE && strstr(dev, "::")))
    {
        SET_ERROR(modinst, "%s: Invalid interface specification: '%s'!", __func__, nmc->device);
        goto err;
    }

    while (*dev != '\0')
    {
        len = strcspn(dev, ":");
        if (len >= sizeof(intf))
        {
            SET_ERROR(modinst, "%s: Interface name too long! (%zu)", __func__, len);
            goto err;
        }
        if (len != 0)
        {
            nmc->intf_count++;
            if (nmc->intf_count >= NETMAP_MAX_INTERFACES)
            {
                SET_ERROR(modinst, "%s: Using more than %d interfaces is not supported!",
                            __func__, NETMAP_MAX_INTERFACES);
                goto err;
            }
            snprintf(intf, len + 1, "%s", dev);
            NetmapInstance *instance = create_instance(intf, nmc->instances, modinst);
            if (!instance)
                goto err;

            instance->next = nmc->instances;
            nmc->instances = instance;
            num_intfs++;
            if (mode != DAQ_MODE_PASSIVE)
            {
                if (num_intfs == 2)
                {
                    const char *name1 = nmc->instances->next->req.nr_name;
                    const char *name2 = nmc->instances->req.nr_name;

                    if (create_bridge(nmc, name1, name2) != DAQ_SUCCESS)
                    {
                        SET_ERROR(modinst, "%s: Couldn't create the bridge between %s and %s!",
                                    __func__, name1, name2);
                        goto err;
                    }
                    num_intfs = 0;
                }
                else if (num_intfs > 2)
                    break;
            }
        }
        else
            len = 1;
        dev += len;
    }

    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (!nmc->instances || (mode != DAQ_MODE_PASSIVE && num_intfs != 0))
    {
        SET_ERROR(modinst, "%s: Invalid interface specification: '%s'!",
                    __func__, nmc->device);
        goto err;
    }

    /* Initialize other default configuration values. */
    nmc->debug = false;

    /* Import the configuration dictionary requests. */
    const char *varKey, *varValue;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "debug"))
            nmc->debug = true;

        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    /* Finally, create the message buffer pool. */
    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    if (pool_size == 0)
    {
        /* Default the pool size to 256 descriptors per interface for now. */
        pool_size = nmc->intf_count * 256;
    }
    if ((rval = create_packet_pool(nmc, pool_size)) != DAQ_SUCCESS)
        goto err;

    nmc->curr_instance = nmc->instances;

    *ctxt_ptr = nmc;

    return DAQ_SUCCESS;

err:
    if (nmc)
    {
        netmap_close(nmc);
        if (nmc->device)
            free(nmc->device);
        destroy_packet_pool(nmc);
        free(nmc);
    }
    return rval;
}

static void netmap_daq_destroy(void *handle)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    netmap_close(nmc);
    if (nmc->device)
        free(nmc->device);
    destroy_packet_pool(nmc);
    free(nmc);
}

static int netmap_daq_start(void *handle)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;
    NetmapInstance *instance;

    for (instance = nmc->instances; instance; instance = instance->next)
    {
        if (start_instance(nmc, instance) != DAQ_SUCCESS)
            return DAQ_ERROR;
    }

    memset(&nmc->stats, 0, sizeof(DAQ_Stats_t));;

    return DAQ_SUCCESS;
}

static int wait_for_tx_slot(Netmap_Context_t *nmc, NetmapInstance *instance)
{
    struct pollfd pfd;

    pfd.fd = instance->fd;
    pfd.revents = 0;
    pfd.events = POLLOUT;

    int ret = poll(&pfd, 1, -1);
    if (ret > 0)
    {
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
        {
            if (pfd.revents & POLLHUP)
                SET_ERROR(nmc->modinst, "%s: Hang-up on a packet socket", __func__);
            else if (pfd.revents & POLLERR)
                SET_ERROR(nmc->modinst, "%s: Encountered error condition on a packet socket", __func__);
            else if (pfd.revents & POLLNVAL)
                SET_ERROR(nmc->modinst, "%s: Invalid polling request on a packet socket", __func__);
            return DAQ_ERROR;
        }
        /* All good! A TX slot should be waiting for us somewhere. */
        return DAQ_SUCCESS;
    }
    /* If we were interrupted by a signal, start the loop over.  The user should call daq_interrupt to actually exit. */
    if (ret < 0 && errno != EINTR)
    {
        SET_ERROR(nmc->modinst, "%s: Poll failed: %s (%d)", __func__, strerror(errno), errno);
        return DAQ_ERROR;
    }

    return DAQ_ERROR_AGAIN;
}

static inline int netmap_transmit_packet(NetmapInstance *egress, const uint8_t *packet_data, unsigned int len)
{
    /* Find a TX ring with space to send on. */
    uint16_t start_tx_ring = egress->cur_tx_ring;
    do
    {
        struct netmap_ring *tx_ring = NETMAP_TXRING(egress->nifp, egress->cur_tx_ring);
        nminst_inc_tx_ring(egress);
        if (nm_ring_empty(tx_ring))
            continue;

        uint32_t tx_cur = tx_ring->cur;
        struct netmap_slot *tx_slot = &tx_ring->slot[tx_cur];
        tx_slot->len = len;
        nm_pkt_copy(packet_data, NETMAP_BUF(tx_ring, tx_slot->buf_idx), tx_slot->len);

        tx_ring->head = tx_ring->cur = nm_ring_next(tx_ring, tx_cur);

        return DAQ_SUCCESS;
    } while (egress->cur_tx_ring != start_tx_ring);

    /* If we got here, it means we couldn't find an available TX slot. */
    return DAQ_ERROR_AGAIN;
}

static int netmap_inject_packet(Netmap_Context_t *nmc, NetmapInstance *egress, const uint8_t *data, uint32_t data_len)
{
    if (!egress)
    {
        SET_ERROR(nmc->modinst, "%s: Could not determine which instance to inject the packet out of!", __func__);
        return DAQ_ERROR;
    }

    int rval = netmap_transmit_packet(egress, data, data_len);
    if (rval != DAQ_SUCCESS)
    {
        if (rval == DAQ_ERROR_AGAIN)
            SET_ERROR(nmc->modinst, "%s: Could not send packet because no TX slots were available.", __func__);
        else
            SET_ERROR(nmc->modinst, "%s: Error sending packet: %s (%d)", __func__, strerror(errno), errno);
        return rval;
    }

    nmc->stats.packets_injected++;

    return DAQ_SUCCESS;
}

static int netmap_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    if (type != DAQ_MSG_TYPE_PACKET)
        return DAQ_ERROR_NOTSUP;

    const DAQ_PktHdr_t *pkthdr = (const DAQ_PktHdr_t *) hdr;
    NetmapInstance *egress;

    /* Find the instance that the packet was received on. */
    for (egress = nmc->instances; egress; egress = egress->next)
    {
        if (egress->index == pkthdr->ingress_index)
            break;
    }

    if (!egress)
    {
        SET_ERROR(nmc->modinst, "%s: Unrecognized ingress interface specified: %u",
                __func__, pkthdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    return netmap_inject_packet(nmc, egress, data, data_len);
}

static int netmap_daq_inject_relative(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;
    NetmapPktDesc *desc = (NetmapPktDesc *) msg->priv;
    NetmapInstance *egress = reverse ? desc->instance : desc->instance->peer;

    if (!reverse && !egress)
    {
        SET_ERROR(nmc->modinst, "%s: Specified ingress interface has no peer for forward injection.",
                __func__);
        return DAQ_ERROR_NODEV;
    }

    return netmap_inject_packet(nmc, egress, data, data_len);
}

static int netmap_daq_interrupt(void *handle)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    nmc->interrupted = true;

    return DAQ_SUCCESS;
}

static int netmap_daq_stop(void *handle)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    netmap_close(nmc);

    return DAQ_SUCCESS;
}

static int netmap_daq_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    /* Only supports GET_DEVICE_INDEX for now */
    if (cmd != DIOCTL_GET_DEVICE_INDEX || arglen != sizeof(DIOCTL_QueryDeviceIndex))
        return DAQ_ERROR_NOTSUP;

    DIOCTL_QueryDeviceIndex *qdi = (DIOCTL_QueryDeviceIndex *) arg;

    if (!qdi->device)
    {
        SET_ERROR(nmc->modinst, "No device name to find the index of!");
        return DAQ_ERROR_INVAL;
    }

    for (NetmapInstance *instance = nmc->instances; instance; instance = instance->next)
    {
        if (!strcmp(qdi->device, instance->req.nr_name))
        {
            qdi->index = instance->index;
            return DAQ_SUCCESS;
        }
    }

    return DAQ_ERROR_NODEV;
}

static int netmap_daq_get_stats(void *handle, DAQ_Stats_t * stats)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    memcpy(stats, &nmc->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void netmap_daq_reset_stats(void *handle)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    memset(&nmc->stats, 0, sizeof(DAQ_Stats_t));;
}

static int netmap_daq_get_snaplen(void *handle)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    return nmc->snaplen;
}

static uint32_t netmap_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
            DAQ_CAPA_UNPRIV_START | DAQ_CAPA_INTERRUPT |
            DAQ_CAPA_DEVICE_INDEX;
}

static int netmap_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static inline struct netmap_ring *find_ring(Netmap_Context_t *nmc)
{
    NetmapInstance *instance;

    /* Iterate over the instances' rings to find the first one with data available.
        Keep track of the last checked instance and RX ring within that instance
        to continue the effort on the next call. */
    instance = nmc->curr_instance;
    do
    {
        instance = instance->next ? instance->next : nmc->instances;
        uint16_t start_rx_ring = instance->cur_rx_ring;
        do
        {
            struct netmap_ring *rx_ring = NETMAP_RXRING(instance->nifp, instance->cur_rx_ring);
            nminst_inc_rx_ring(instance);
            if (!nm_ring_empty(rx_ring))
            {
                nmc->curr_instance = instance;
                return rx_ring;
            }
        } while (instance->cur_rx_ring != start_rx_ring);
    } while (instance != nmc->curr_instance);

    return NULL;
}

static inline DAQ_RecvStatus wait_for_packet(Netmap_Context_t *nmc)
{
    NetmapInstance *instance;
    struct pollfd pfd[NETMAP_MAX_INTERFACES];
    uint32_t i;

    for (i = 0, instance = nmc->instances; instance; i++, instance = instance->next)
    {
        pfd[i].fd = instance->fd;
        pfd[i].revents = 0;
        pfd[i].events = POLLIN;
    }
    /* Chop the timeout into one second chunks (plus any remainer) to improve responsiveness to
        interruption when there is no traffic and the timeout is very long (or unlimited). */
    int timeout = nmc->timeout;
    while (timeout != 0)
    {
        /* If the receive has been canceled, break out of the loop and return. */
        if (nmc->interrupted)
        {
            nmc->interrupted = false;
            return DAQ_RSTAT_INTERRUPTED;
        }

        int poll_timeout;
        if (timeout >= 1000)
        {
            poll_timeout = 1000;
            timeout -= 1000;
        }
        else if (timeout > 0)
        {
            poll_timeout = timeout;
            timeout = 0;
        }
        else
            poll_timeout = 1000;

        int ret = poll(pfd, nmc->intf_count, poll_timeout);
        /* If some number of of sockets have events returned, check them all for badness. */
        if (ret > 0)
        {
            for (i = 0; i < nmc->intf_count; i++)
            {
                if (pfd[i].revents & (POLLHUP | POLLERR | POLLNVAL))
                {
                    if (pfd[i].revents & POLLHUP)
                        SET_ERROR(nmc->modinst, "%s: Hang-up on a packet socket", __func__);
                    else if (pfd[i].revents & POLLERR)
                        SET_ERROR(nmc->modinst, "%s: Encountered error condition on a packet socket", __func__);
                    else if (pfd[i].revents & POLLNVAL)
                        SET_ERROR(nmc->modinst, "%s: Invalid polling request on a packet socket", __func__);
                    return DAQ_RSTAT_ERROR;
                }
            }
            /* All good! A packet should be waiting for us somewhere. */
            return DAQ_RSTAT_OK;
        }
        /* If we were interrupted by a signal, start the loop over.  The user should call daq_interrupt to actually exit. */
        if (ret < 0 && errno != EINTR)
        {
            SET_ERROR(nmc->modinst, "%s: Poll failed: %s (%d)", __func__, strerror(errno), errno);
            return DAQ_RSTAT_ERROR;
        }
    }

    return DAQ_RSTAT_TIMEOUT;
}

static unsigned netmap_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    unsigned idx = 0;

    while (idx < max_recv)
    {
        /* Check to see if the receive has been canceled.  If so, reset it and return appropriately. */
        if (nmc->interrupted)
        {
            nmc->interrupted = false;
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        /* Make sure that we have a packet descriptor available to populate. */
        NetmapPktDesc *desc = nmc->pool.freelist;
        if (!desc)
        {
            status = DAQ_RSTAT_NOBUF;
            break;
        }

        /* Try to find a packet ready for processing from one of the RX rings. */
        struct netmap_ring *rx_ring = find_ring(nmc);
        if (!rx_ring)
        {
            /* Only block waiting for a packet if we haven't received anything yet. */
            if (idx != 0)
            {
                status = DAQ_RSTAT_WOULD_BLOCK;
                break;
            }
            status = wait_for_packet(nmc);
            if (status != DAQ_RSTAT_OK)
                break;
            continue;
        }

        NetmapInstance *instance;

        uint32_t rx_cur = rx_ring->cur;
        struct netmap_slot *rx_slot = &rx_ring->slot[rx_cur];
        uint16_t len = rx_slot->len;
        instance = nmc->curr_instance;

        uint8_t *data = (uint8_t *) NETMAP_BUF(rx_ring, rx_slot->buf_idx);

        nmc->stats.packets_received++;

        /* Populate the packet descriptor, copying the packet data and releasing the packet
           ring entry back to the kernel for reuse. */
        memcpy(desc->data, data, len);
        rx_ring->head = rx_ring->cur = nm_ring_next(rx_ring, rx_cur);
        desc->instance = instance;
        desc->length = len;

        /* Next, set up the DAQ message.  Most fields are prepopulated and unchanging. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->data_len = len;
        msg->data = data;

        /* Then, set up the DAQ packet header. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ts = rx_ring->ts;
        pkthdr->pktlen = len;
        pkthdr->ingress_index = instance->index;
        pkthdr->egress_index = instance->peer ? instance->peer->index : DAQ_PKTHDR_UNKNOWN;
        pkthdr->flags = 0;
        /* The following fields should remain in their virgin state:
            address_space_id (0)
            ingress_group (DAQ_PKTHDR_UNKNOWN)
            egress_group (DAQ_PKTHDR_UNKNOWN)
            opaque (0)
            flow_id (0)
         */

        /* Last, but not least, extract this descriptor from the free list and
           place the message in the return vector. */
        nmc->pool.freelist = desc->next;
        desc->next = NULL;
        nmc->pool.info.available--;
        msgs[idx] = &desc->msg;

        idx++;
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

static int netmap_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;
    NetmapPktDesc *desc = (NetmapPktDesc *) msg->priv;
    NetmapInstance *peer;

    /* Sanitize and enact the verdict. */
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    nmc->stats.verdicts[verdict]++;
    verdict = verdict_translation_table[verdict];
    if (verdict == DAQ_VERDICT_PASS && (peer = desc->instance->peer))
    {
        int ret = netmap_transmit_packet(peer, desc->data, desc->length);
        if (ret == DAQ_ERROR_AGAIN && wait_for_tx_slot(nmc, peer) == DAQ_SUCCESS)
        {
            if (netmap_transmit_packet(peer, desc->data, desc->length) != DAQ_SUCCESS)
                peer->tx_discards++;
        }
    }

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = nmc->pool.freelist;
    nmc->pool.freelist = desc;
    nmc->pool.info.available++;

    return DAQ_SUCCESS;
}

static int netmap_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    Netmap_Context_t *nmc = (Netmap_Context_t *) handle;

    *info = nmc->pool.info;

    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t netmap_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_NETMAP_VERSION,
    /* .name = */ "netmap",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ netmap_daq_module_load,
    /* .unload = */ netmap_daq_module_unload,
    /* .get_variable_descs = */ netmap_daq_get_variable_descs,
    /* .instantiate = */ netmap_daq_instantiate,
    /* .destroy = */ netmap_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ netmap_daq_start,
    /* .inject = */ netmap_daq_inject,
    /* .inject_relative = */ netmap_daq_inject_relative,
    /* .interrupt = */ netmap_daq_interrupt,
    /* .stop = */ netmap_daq_stop,
    /* .ioctl = */ netmap_daq_ioctl,
    /* .get_stats = */ netmap_daq_get_stats,
    /* .reset_stats = */ netmap_daq_reset_stats,
    /* .get_snaplen = */ netmap_daq_get_snaplen,
    /* .get_capabilities = */ netmap_daq_get_capabilities,
    /* .get_datalink_type = */ netmap_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ netmap_daq_msg_receive,
    /* .msg_finalize = */ netmap_daq_msg_finalize,
    /* .get_msg_pool_info = */ netmap_daq_get_msg_pool_info,
};

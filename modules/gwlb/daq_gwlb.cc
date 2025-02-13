/*
** Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
** Author: Raman S. Krishnan <ramanks@cisco.com>
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

#include <stdio.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>

#include <daq.h>
#include <daq_module_api.h>
#include <daq_common.h>

#define DAQ_NAME            "gwlb"
#define DAQ_MOD_VERSION     1

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

#define CALL_SUBAPI(ctxt, fname, ...) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context, __VA_ARGS__)

#define CALL_SUBAPI_NOARGS(ctxt, fname) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context)

struct vlan_header {
    uint16_t                    tpid;
    uint16_t                    ether_type;
};

struct GWLBContext
{
    DAQ_ModuleInstance_h modinst;
    DAQ_InstanceAPI_t subapi;
    uint8_t hwaddr[ ETH_ALEN ];
};

static DAQ_BaseAPI_t daq_base_api;

static int gwlb_daq_module_load(const DAQ_BaseAPI_t* base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int gwlb_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int gwlb_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    GWLBContext* ctx;
    const char* ifname;
    struct ifreq ifr;
    int sock;
    int rc;

    ctx = new GWLBContext();
    if (!ctx)
    {
        SET_ERROR(modinst, "daq_gwlb: Could not allocate memory for a new context: %m");
        return DAQ_ERROR_NOMEM;
    }

    ctx->modinst = modinst;
    if (daq_base_api.resolve_subapi(modinst, &ctx->subapi) != DAQ_SUCCESS)
    {
        SET_ERROR(modinst, "daq_gwlb: Couldn't resolve subapi");
        delete ctx;
        return DAQ_ERROR_INVAL;
    }

    ifname = daq_base_api.config_get_input(modcfg);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        SET_ERROR(ctx->modinst, "daq_gwlb: Cannot open socket: %m");
        delete ctx;
        return DAQ_ERROR;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    rc = ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);

    if (rc < 0)
    {
        SET_ERROR(ctx->modinst, "daq_gwlb: Unable to get HW address of %s: %m", ifname);
        delete ctx;
        return DAQ_ERROR_NODEV;
    }

    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
    {
        SET_ERROR(ctx->modinst, "daq_gwlb: Unsupported address family %d on device %s",
                ifr.ifr_hwaddr.sa_family, ifname);
        delete ctx;
        return DAQ_ERROR_INVAL;
    }

    memcpy(ctx->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    *ctxt_ptr = ctx;

    return DAQ_SUCCESS;
}

static void gwlb_daq_destroy(void* handle)
{
    GWLBContext* ctx = static_cast<GWLBContext*>(handle);

    delete ctx;
}

static void swap_l2_addr (uint8_t* data, uint32_t dlen)
{
    struct ether_header* eth;
    uint8_t* da;
    uint8_t* sa;
    uint8_t tmp;
    int idx;

    if (dlen < sizeof(struct ether_header))
        return;

    eth = reinterpret_cast<struct ether_header*>(data);
    da = eth->ether_dhost;
    sa = eth->ether_shost;

    for (idx = 0; idx < ETH_ALEN; idx++)
    {
        tmp     =   *da;
        *da++   =   *sa;
        *sa++   =   tmp;
    }
}

static int is_vlan_type (uint16_t et)
{
    int                         ret;

    switch (et) {
    case    ETH_P_8021Q:
    case    ETH_P_QINQ1:
    case    ETH_P_QINQ2:
    case    ETH_P_QINQ3:
        ret     =   true;
        break;

    default:
        ret     =   false;
        break;
    }

    return (ret);
}

static void swap_ipv4 (struct iphdr* hdr)
{
    uint32_t tmp;

    tmp = hdr->daddr;
    hdr->daddr = hdr->saddr;
    hdr->saddr = tmp;
}

static void swap_ipv6 (struct ip6_hdr* hdr)
{
    struct in6_addr tmp;

    tmp = hdr->ip6_dst;
    hdr->ip6_dst = hdr->ip6_src;
    hdr->ip6_src = tmp;
}

static void swap_l3_addr (uint8_t* data, uint32_t dlen)
{
    struct ether_header* eth;
    struct vlan_header* vhdr;
    uint8_t* ptr;
    uint16_t et;

    ptr = data;
    eth = reinterpret_cast<struct ether_header*>(ptr);
    ptr  += sizeof(struct ether_header);
    dlen -= sizeof(struct ether_header);

    et =   ntohs(eth->ether_type);

    while (is_vlan_type(et) && (dlen > 0))
    {
        vhdr = reinterpret_cast<struct vlan_header*>(ptr);
        ptr += sizeof(struct vlan_header);
        dlen -= sizeof(struct vlan_header);

        et = ntohs(vhdr->ether_type);
    }

    if (et == ETH_P_IP)
    {
        if (dlen >= sizeof(struct iphdr))
            swap_ipv4((struct iphdr* ) ptr);
    }
    else if (et == ETH_P_IPV6)
    {
        if (dlen >= sizeof(struct ip6_hdr))
            swap_ipv6((struct ip6_hdr* ) ptr);
    }
}

static inline void swap_addr(uint8_t* ptr, uint32_t dlen)
{
    swap_l2_addr(ptr, dlen);
    swap_l3_addr(ptr, dlen);
}

static int gwlb_daq_finalize (void* handle, const DAQ_Msg_t* msg, DAQ_Verdict verdict)
{
    GWLBContext* ctx = static_cast<GWLBContext*>(handle);
    uint8_t* pktstart = const_cast<uint8_t* >(daq_msg_get_data(msg));
    uint32_t pktlen = daq_msg_get_data_len(msg);

    swap_addr(pktstart, pktlen);

    return CALL_SUBAPI(ctx, msg_finalize, msg, verdict);
}

static int gwlb_daq_inject (void* handle, DAQ_MsgType type, const void* hdr, const uint8_t* data, uint32_t dlen)
{
    GWLBContext* ctx = static_cast<GWLBContext*>(handle);
    uint8_t* pktstart = const_cast<uint8_t* >(data);

    if (!memcmp(ctx->hwaddr, pktstart, ETH_ALEN))
    {
        swap_addr(pktstart, dlen);
    }

    return CALL_SUBAPI(ctx, inject, type, hdr, data, dlen);
}

static int gwlb_daq_inject_relative (void* handle, const DAQ_Msg_t* msg, const uint8_t* data, uint32_t dlen, int reverse)
{
    GWLBContext* ctx = static_cast<GWLBContext*>(handle);
    uint8_t* pktstart = const_cast<uint8_t* >(data);

    if (!memcmp(ctx->hwaddr, pktstart, ETH_ALEN))
    {
        swap_addr(pktstart, dlen);
    }

    return CALL_SUBAPI(ctx, inject_relative, msg, data, dlen, reverse);
}

static uint32_t gwlb_daq_get_capabilities(void *handle)
{
    GWLBContext* ctx = static_cast<GWLBContext*>(handle);

    return (CALL_SUBAPI_NOARGS(ctx, get_capabilities) | DAQ_CAPA_DECODE_GENEVE);
}


extern "C" {
#ifdef BUILDING_SO
DAQ_SO_PUBLIC DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
DAQ_ModuleAPI_t gwlb_daq_module_data =
#endif
{
    /* .api_version = */        DAQ_MODULE_API_VERSION,
    /* .api_size = */           sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */     DAQ_MOD_VERSION,
    /* .name = */               DAQ_NAME,
    /* .type = */               (DAQ_TYPE_WRAPPER | DAQ_TYPE_INLINE_CAPABLE),
    /* .load = */               gwlb_daq_module_load,
    /* .unload = */             gwlb_daq_module_unload,
    /* .get_variable_descs = */ NULL,
    /* .instantiate = */        gwlb_daq_instantiate,
    /* .destroy = */            gwlb_daq_destroy,
    /* .set_filter = */         NULL,
    /* .start = */              NULL,
    /* .inject = */             gwlb_daq_inject,
    /* .inject_relative = */    gwlb_daq_inject_relative,
    /* .interrupt = */          NULL,
    /* .stop = */               NULL,
    /* .ioctl = */              NULL,
    /* .get_stats = */          NULL,
    /* .reset_stats = */        NULL,
    /* .get_snaplen = */        NULL,
    /* .get_capabilities = */   gwlb_daq_get_capabilities,
    /* .get_datalink_type = */  NULL,
    /* .config_load = */        NULL,
    /* .config_swap = */        NULL,
    /* .config_free = */        NULL,
    /* .msg_receive = */        NULL,
    /* .msg_finalize = */       gwlb_daq_finalize,
    /* .get_msg_pool_info = */  NULL,
};
}

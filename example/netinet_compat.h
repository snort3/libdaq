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

#ifndef _NETINET_COMPAT_H
#define _NETINET_COMPAT_H

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__darwin__) || defined(__OpenBSD__)
#include <sys/socket.h>     // Needed for struct sockaddr and int types
#endif

#if defined(__OpenBSD__)
#include <net/if_arp.h>     // Needed for struct arphdr
#endif

#include <netinet/if_ether.h>

typedef struct arphdr EthArpHdr;
typedef struct ether_arp EthArp;
typedef struct ether_header EthHdr;

#include <netinet/in.h>

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

#include <netinet/tcp.h>

typedef struct tcphdr TcpHdr;

#include <netinet/udp.h>

typedef struct udphdr UdpHdr;

#if defined(__linux__)

#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>

typedef struct iphdr IpHdr;
typedef struct icmphdr IcmpHdr;
typedef struct ip6_hdr Ip6Hdr;
typedef struct ip6_ext Ip6Ext;
typedef struct ip6_frag Ip6Frag;
typedef struct icmp6_hdr Icmp6Hdr;

#else

#define       IP_MAXPACKET    65535           /* maximum packet size */
#define       IP_DF		      0x4000		  /* don't fragment flag */
#define       IP_MF           0x2000          /* more fragments flag */
#define       IP_OFFMASK      0x1fff          /* mask for fragmenting bits */
typedef struct _ip_hdr
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error "Unknown endianness!"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
} IpHdr;

#define ICMP_ECHOREPLY      0   /* Echo Reply           */
#define ICMP_ECHO           8   /* Echo Request         */
typedef struct _icmp_hdr
{
    uint8_t type;     /* message type */
    uint8_t code;     /* type sub-code */
    uint16_t checksum;
    union
    {
        struct
        {
            uint16_t  id;
            uint16_t  sequence;
        } echo;         /* echo datagram */
        uint32_t    gateway;    /* gateway address */
        struct
        {
            uint16_t  __glibc_reserved;
            uint16_t  mtu;
        } frag;         /* path mtu discovery */
    } un;
} IcmpHdr;

typedef struct _ip6_hdr
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
                                        20 bits flow-ID */
            uint16_t ip6_un1_plen;   /* payload length */
            uint8_t  ip6_un1_nxt;    /* next header */
            uint8_t  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
    } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
} Ip6Hdr;
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt

/* Generic extension header.  */
typedef struct _ip6_ext
{
    uint8_t  ip6e_nxt;      /* next header.  */
    uint8_t  ip6e_len;      /* length in units of 8 octets.  */
} Ip6Ext;

/* Fragment header */
typedef struct _ip6_frag
{
    uint8_t   ip6f_nxt;     /* next header */
    uint8_t   ip6f_reserved;    /* reserved field */
    uint16_t  ip6f_offlg;   /* offset, reserved, and flag */
    uint32_t  ip6f_ident;   /* identification */
} Ip6Frag;

#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129
typedef struct _icmp6_hdr
{
    uint8_t     icmp6_type;   /* type field */
    uint8_t     icmp6_code;   /* code field */
    uint16_t    icmp6_cksum;  /* checksum field */
    union
    {
        uint32_t  icmp6_un_data32[1]; /* type-specific field */
        uint16_t  icmp6_un_data16[2]; /* type-specific field */
        uint8_t   icmp6_un_data8[4];  /* type-specific field */
    } icmp6_dataun;
} Icmp6Hdr;
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_id        icmp6_data16[0]  /* echo request/reply */
#define icmp6_seq       icmp6_data16[1]  /* echo request/reply */

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__darwin__) || defined(__OpenBSD__)
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#endif

#endif /* _NETINET_COMPAT_H */

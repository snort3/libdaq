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

#ifndef _DECODE_H
#define _DECODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "daq_common.h"
#include "netinet_compat.h"

/* Relevant ethertypes lifted from Linux's if_ether.h since there doesn't seem to be a reliable
    cross-platform way of obtaining all of them. */
#define ETYPE_MIN       1536        /* smaller values encode 802.3 length */
#define ETYPE_ARP       0x0806      /* Address Resolution packet    */
#define ETYPE_IP        0x0800      /* Internet Protocol packet */
#define ETYPE_IPV6      0x86DD      /* IPv6 over bluebook       */
#define ETYPE_8021Q     0x8100      /* 802.1Q VLAN Extended Header  */
#define ETYPE_8021AD    0x88A8      /* 802.1ad Service VLAN         */
#define ETYPE_QINQ1     0x9100      /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETYPE_QINQ2     0x9200      /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETYPE_QINQ3     0x9300      /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */

#define VTH_PRIORITY(vh)  ((unsigned short)((ntohs((vh)->vth_pri_cfi_vlan) & 0xe000) >> 13))
#define VTH_CFI(vh)       ((ntohs((vh)->vth_pri_cfi_vlan) & 0x0100) >> 12)
#define VTH_VLAN(vh)      ((unsigned short)(ntohs((vh)->vth_pri_cfi_vlan) & 0x0FFF))
typedef struct
{
    uint16_t vth_pri_cfi_vlan;
    uint16_t vth_proto;  /* protocol field... */
} VlanTagHdr;

#define SNAP_SAPS       0xaaaa
typedef struct
{
    uint16_t sh_dsap_ssap;
    uint16_t sh_ctl_oc0;
    uint16_t sh_oc1_oc2;
    uint16_t sh_proto;
} SnapHdr;

typedef struct
{
    DAQ_PktDecodeData_t decoded_data;
    const uint8_t *packet_data;
    const EthHdr *eth;
    const VlanTagHdr *vlan;
    const EthArpHdr *arp;
    const IpHdr *ip;
    const Ip6Hdr *ip6;
    const IcmpHdr *icmp;
    const Icmp6Hdr *icmp6;
    const TcpHdr *tcp;
    const UdpHdr *udp;
    uint16_t vlan_tags;
    bool ignore_checksums;
    bool tcp_data_segment;
} DecodeData;

/*
 * Simple implementation of "the Internet Checksum" AKA a one's complement of a one's complement summation (16-bit).
 * Lifted from RFC1071 (+ errata).
 * Takes a vector of pointers to data and lengths to handle things like including noncontiguous pseudoheaders.
 */
struct cksum_vec {
    const uint16_t *addr;
    uint32_t len;
};
static inline uint16_t in_cksum_vec(struct cksum_vec *vec, unsigned vec_len)
{
    uint32_t sum = 0;

    for (; vec_len != 0; vec++, vec_len--)
    {
        const uint16_t *addr = vec->addr;
        uint32_t len = vec->len;

        /* Compute Internet Checksum for "len" bytes beginning at location "addr". */
        while (len > 1) {
            sum += *addr++;
            len -= 2;
        }

        /* Add left-over byte, if any */
        if (len > 0) {
            uint16_t left_over = 0;
            *(uint8_t *) &left_over = *(const uint8_t *) addr;
            sum += left_over;
        }
    }

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

static inline uint16_t in_cksum_v4(const IpHdr *ip, const uint16_t *data, uint16_t len, uint8_t proto)
{
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } ph;
    ph.src = ip->saddr;
    ph.dst = ip->daddr;
    ph.zero = 0;
    ph.proto = proto;
    ph.len = htons(len);

    struct cksum_vec vec[2];
    vec[0].addr = (const uint16_t *) &ph;
    vec[0].len = sizeof(ph);
    vec[1].addr = (const uint16_t *) data;
    vec[1].len = len;

    return in_cksum_vec(vec, 2);
}

static inline uint16_t in_cksum_v6(const Ip6Hdr *ip6, const uint16_t *data, uint32_t len, uint8_t proto)
{
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t nxt;
    } ph;
    memcpy(&ph.src, &ip6->ip6_src, sizeof(ph.src));
    memcpy(&ph.dst, &ip6->ip6_dst, sizeof(ph.dst));
    ph.len = htonl(len);
    ph.zero[0] = ph.zero[1] = ph.zero[2] = 0;
    ph.nxt = proto;

    struct cksum_vec vec[2];
    vec[0].addr = (const uint16_t *) &ph;
    vec[0].len = sizeof(ph);
    vec[1].addr = (const uint16_t *) data;
    vec[1].len = len;

    return in_cksum_vec(vec, 2);
}

static inline void update_pyld_csum_offsets(const uint8_t *cursor, DecodeData *dd)
{
    dd->decoded_data.payload_offset = cursor - dd->packet_data;
    if (!dd->decoded_data.flags.bits.checksum_error)
        dd->decoded_data.checksum_offset = dd->decoded_data.payload_offset;
}

static inline bool decode_icmp(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    update_pyld_csum_offsets(cursor, dd);
    dd->decoded_data.l4_offset = cursor - dd->packet_data;

    if (len < sizeof(IcmpHdr))
        return false;
    const IcmpHdr *icmp = (const IcmpHdr *) cursor;

    struct cksum_vec vec = { (const uint16_t *) icmp, len };
    if (in_cksum_vec(&vec, 1) != 0)
    {
        dd->decoded_data.flags.bits.checksum_error = true;
        if (!dd->ignore_checksums)
            return false;
    }
    else
        dd->decoded_data.flags.bits.l4_checksum = true;

    dd->icmp = icmp;
    dd->decoded_data.flags.bits.l4 = true;
    dd->decoded_data.flags.bits.icmp = true;

    cursor += sizeof(*icmp);
    update_pyld_csum_offsets(cursor, dd);

    return true;
}

static inline bool decode_icmp6(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    update_pyld_csum_offsets(cursor, dd);
    dd->decoded_data.l4_offset = cursor - dd->packet_data;

    if (len < sizeof(Icmp6Hdr))
        return false;
    const Icmp6Hdr *icmp6 = (const Icmp6Hdr *) cursor;

    if (in_cksum_v6(dd->ip6, (const uint16_t *) icmp6, len, IPPROTO_ICMPV6) != 0)
    {
        dd->decoded_data.flags.bits.checksum_error = true;
        if (!dd->ignore_checksums)
            return false;
    }
    else
        dd->decoded_data.flags.bits.l4_checksum = true;

    dd->icmp6 = icmp6;
    dd->decoded_data.flags.bits.l4 = true;
    dd->decoded_data.flags.bits.icmp = true;

    cursor += sizeof(*icmp6);
    update_pyld_csum_offsets(cursor, dd);

    return true;
}

static inline bool decode_tcp_opts(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    while (len > 0)
    {
        uint8_t opt = cursor[0];

        if (opt == TCPOPT_EOL)
            return true;

        if (opt == TCPOPT_NOP)
        {
            cursor++;
            len--;
            continue;
        }

        if (len < 2)
            return false;

        uint8_t optlen = cursor[1];
        if (optlen < 2 || len < optlen)
            return false;

        switch (opt)
        {
            case TCPOPT_MAXSEG:
                if (optlen != TCPOLEN_MAXSEG)
                    return false;
                dd->decoded_data.flags.bits.tcp_opt_mss = true;
                break;

            case TCPOPT_WINDOW:
                if (optlen != TCPOLEN_WINDOW)
                    return false;
                dd->decoded_data.flags.bits.tcp_opt_ws = true;
                break;

            case TCPOPT_SACK_PERMITTED:
                if (optlen != TCPOLEN_SACK_PERMITTED)
                    return false;
                break;

            case TCPOPT_SACK:
                break;

            case TCPOPT_TIMESTAMP:
                if (optlen != TCPOLEN_TIMESTAMP)
                    return false;
                dd->decoded_data.flags.bits.tcp_opt_ts = true;
                break;

            default:
                /* Unrecognized option, no validation; hope for the best. */
                break;
        }

        cursor += optlen;
        len -= optlen;
    }

    return (len == 0);
}

static inline bool decode_tcp(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    update_pyld_csum_offsets(cursor, dd);
    dd->decoded_data.l4_offset = cursor - dd->packet_data;

    if (len < sizeof(TcpHdr))
        return false;
    const TcpHdr *tcp = (const TcpHdr *) cursor;
    uint16_t hlen = tcp->th_off * 4;
    if (hlen < sizeof(*tcp) || hlen > len)
        return false;

    if (dd->ip)
    {
        if (in_cksum_v4(dd->ip, (const uint16_t *) tcp, len, IPPROTO_TCP) != 0)
        {
            dd->decoded_data.flags.bits.checksum_error = true;
            if (!dd->ignore_checksums)
                return false;
        }
        else
            dd->decoded_data.flags.bits.l4_checksum = true;
    }
    else
    {
        if (in_cksum_v6(dd->ip6, (const uint16_t *) tcp, len, IPPROTO_TCP) != 0)
        {
            dd->decoded_data.flags.bits.checksum_error = true;
            if (!dd->ignore_checksums)
                return false;
        }
        else
            dd->decoded_data.flags.bits.l4_checksum = true;
    }

    uint16_t optlen = hlen - sizeof(*tcp);
    if (optlen && !decode_tcp_opts(cursor + sizeof(*tcp), optlen, dd))
        return false;

    dd->tcp = tcp;
    dd->decoded_data.flags.bits.l4 = true;
    dd->decoded_data.flags.bits.tcp = true;
    dd->tcp_data_segment = (len > hlen) ? true : false;

    cursor += hlen;
    update_pyld_csum_offsets(cursor, dd);

    return true;
}

static inline bool decode_udp(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    update_pyld_csum_offsets(cursor, dd);
    dd->decoded_data.l4_offset = cursor - dd->packet_data;

    if (len < sizeof(UdpHdr))
        return false;
    const UdpHdr *udp = (const UdpHdr *) cursor;
    uint16_t ulen = ntohs(udp->uh_ulen);
    if (ulen < sizeof(*udp) || ulen != len)
        return false;

    if (dd->ip)
    {
        if (in_cksum_v4(dd->ip, (const uint16_t *) udp, len, IPPROTO_UDP) != 0)
        {
            dd->decoded_data.flags.bits.checksum_error = true;
            if (!dd->ignore_checksums)
                return false;
        }
        else
            dd->decoded_data.flags.bits.l4_checksum = true;
    }
    else
    {
        if (in_cksum_v6(dd->ip6, (const uint16_t *) udp, len, IPPROTO_UDP) != 0)
        {
            dd->decoded_data.flags.bits.checksum_error = true;
            if (!dd->ignore_checksums)
                return false;
        }
        else
            dd->decoded_data.flags.bits.l4_checksum = true;
    }

    dd->udp = udp;
    dd->decoded_data.flags.bits.l4 = true;
    dd->decoded_data.flags.bits.udp = true;

    cursor += sizeof(*udp);
    update_pyld_csum_offsets(cursor, dd);

    return true;
}

static inline bool decode_ip6(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    update_pyld_csum_offsets(cursor, dd);
    dd->decoded_data.l3_offset = cursor - dd->packet_data;

    if (len < sizeof(Ip6Hdr))
        return false;

    const Ip6Hdr *ip6 = (const Ip6Hdr *) cursor;
    if ((ntohl(ip6->ip6_flow) >> 28) != 6)
        return false;

    uint32_t plen = ntohs(ip6->ip6_plen);
    uint16_t offset = sizeof(*ip6);
    /* Allow the buffer length to exceed the total length from the IP header to account for
        Ethernet frame trailers/padding.  Adjust the length going forward accordingly. */
    if (len > offset + plen)
        len = offset + plen;

    dd->ip6 = ip6;
    dd->decoded_data.flags.bits.l3 = true;
    dd->decoded_data.flags.bits.ipv6 = true;

    uint8_t next_hdr = ip6->ip6_nxt;
    while (offset < len)
    {
        switch (next_hdr)
        {
            case IPPROTO_FRAGMENT:
            {
                if (sizeof(Ip6Frag) > (len - offset))
                    return false;
                const Ip6Frag *frag = (const Ip6Frag *) (cursor + offset);
                next_hdr = frag->ip6f_nxt;
                offset += sizeof(*frag);
                break;
            }
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS:
            case IPPROTO_MH:
            {
                if (sizeof(Ip6Ext) > (len - offset))
                    return false;
                const Ip6Ext *ext = (const Ip6Ext *) (cursor + offset);
                next_hdr = ext->ip6e_nxt;
                offset += (ext->ip6e_len + 1) << 3;
                break;
            }
            case IPPROTO_TCP:
                return decode_tcp(cursor + offset, len - offset, dd);
            case IPPROTO_UDP:
                return decode_udp(cursor + offset, len - offset, dd);
            case IPPROTO_ICMPV6:
                return decode_icmp6(cursor + offset, len - offset, dd);
            case IPPROTO_NONE:
            default:
                /* If there was still payload left and we got NONE or there's another protocol
                    or extension that we don't recognize, just fail the decode for now. */
                return false;
        }
    }

    cursor += offset;
    update_pyld_csum_offsets(cursor, dd);

    return true;
}

static inline bool decode_ip(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    update_pyld_csum_offsets(cursor, dd);
    dd->decoded_data.l3_offset = cursor - dd->packet_data;

    if (len < sizeof(IpHdr))
        return false;

    const IpHdr *ip = (const IpHdr *) cursor;
    if (ip->version != 4)
        return false;

    uint16_t hlen = ip->ihl * 4;
    if (hlen < 20)
        return false;

    uint32_t dlen = ntohs(ip->tot_len);
    /* Allow the buffer length to exceed the total length from the IP header to account for
        Ethernet frame trailers/padding.  Adjust the length going forward accordingly. */
    if (len > dlen)
        len = dlen;

    if (dlen > len || dlen < hlen)
        return false;

    struct cksum_vec vec = { (const uint16_t *) ip, hlen };
    if (in_cksum_vec(&vec, 1) != 0)
    {
        dd->decoded_data.flags.bits.checksum_error = true;

        if (!dd->ignore_checksums)
            return false;
    }
    else
        dd->decoded_data.flags.bits.l3_checksum = true;

    dd->ip = ip;
    dd->decoded_data.flags.bits.l3 = true;
    dd->decoded_data.flags.bits.ipv4 = true;

    const uint16_t ipoff = ntohs(ip->frag_off);
    const bool is_fragmented = (ipoff & IP_MF) != 0 || (ipoff & IP_OFFMASK) != 0;
    uint16_t offset = hlen;
    
    if (!is_fragmented) 
    {
        switch (dd->ip->protocol)
        {
            case IPPROTO_TCP:
                return decode_tcp(cursor + offset, len - offset, dd);
            case IPPROTO_UDP:
                return decode_udp(cursor + offset, len - offset, dd);
            case IPPROTO_ICMP:
                return decode_icmp(cursor + offset, len - offset, dd);
        }
    }

    cursor += offset;
    update_pyld_csum_offsets(cursor, dd);

    return true;
}

static inline bool decode_arp(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    update_pyld_csum_offsets(cursor, dd);
    if (len < sizeof(EthArpHdr))
        return false;
    dd->arp = (const EthArpHdr *) cursor;
    return true;
}

static inline bool is_vlan_ethertype(uint16_t ether_type)
{
    switch (ether_type)
    {
        case ETYPE_8021Q:
        case ETYPE_8021AD:
        case ETYPE_QINQ1:
        case ETYPE_QINQ2:
        case ETYPE_QINQ3:
            return true;

        default:
            return false;
    }
}

static inline bool decode_snap(const uint8_t *cursor, uint32_t len, uint16_t *ether_type, uint16_t *offset)
{
    if (*ether_type >= ETYPE_MIN)
        return true;

    if (len < *offset + sizeof(SnapHdr))
        return false;

    const SnapHdr *snap = (const SnapHdr *) (cursor + *offset);
    if (snap->sh_dsap_ssap != htons(SNAP_SAPS))
        return false;

    *ether_type = ntohs(snap->sh_proto);
    *offset += sizeof(*snap);
    return true;
}

static inline bool decode_eth(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    update_pyld_csum_offsets(cursor, dd);
    dd->decoded_data.l2_offset = cursor - dd->packet_data;

    if (len < sizeof(EthHdr))
        return false;

    const EthHdr *eth = (const EthHdr *) cursor;
    uint16_t ether_type = ntohs(eth->ether_type);
    uint16_t offset = sizeof(*eth);

    if (!decode_snap(cursor, len, &ether_type, &offset))
        return false;

    dd->eth = eth;
    dd->decoded_data.flags.bits.l2 = true;
    dd->decoded_data.flags.bits.ethernet = true;

    while (is_vlan_ethertype(ether_type))
    {
        if (offset + sizeof(VlanTagHdr) > len)
            return false;
        const VlanTagHdr *vlan = (const VlanTagHdr *) (cursor + offset);
        ether_type = ntohs(vlan->vth_proto);
        offset += sizeof(*vlan);
        /* Keep track of the innermost VLAN tag and a count of the total */
        dd->vlan = vlan;
        dd->decoded_data.flags.bits.vlan = true;
        dd->vlan_tags++;
        if (dd->vlan_tags > 1)
            dd->decoded_data.flags.bits.vlan_qinq = true;
    }

    if (!decode_snap(cursor, len, &ether_type, &offset))
        return false;

    switch (ether_type)
    {
        case ETYPE_ARP:
            return decode_arp(cursor + offset, len - offset, dd);
        case ETYPE_IP:
            return decode_ip(cursor + offset, len - offset, dd);
        case ETYPE_IPV6:
            return decode_ip6(cursor + offset, len - offset, dd);
    }

    cursor += offset;
    update_pyld_csum_offsets(cursor, dd);

    return true;
}

static inline bool decode_raw(const uint8_t *cursor, uint32_t len, DecodeData *dd)
{
    if (len < 1)
        return false;
    uint8_t ipver = (cursor[0] & 0xf0) >> 4;
    if (ipver == 4)
        return decode_ip(cursor, len, dd);
    if (ipver == 6)
        return decode_ip6(cursor, len, dd);
    return false;
}

static inline void decode_data_init(DecodeData *dd, const uint8_t *packet_data, bool ignore_checksums)
{
    memset(dd, 0, sizeof(*dd));
    dd->packet_data = packet_data;
    dd->decoded_data.l2_offset = DAQ_PKT_DECODE_OFFSET_INVALID;
    dd->decoded_data.l3_offset = DAQ_PKT_DECODE_OFFSET_INVALID;
    dd->decoded_data.l4_offset = DAQ_PKT_DECODE_OFFSET_INVALID;
    dd->decoded_data.payload_offset = DAQ_PKT_DECODE_OFFSET_INVALID;
    dd->decoded_data.checksum_offset = DAQ_PKT_DECODE_OFFSET_INVALID;
    dd->ignore_checksums = ignore_checksums;
}

#ifdef __cplusplus
}
#endif

#endif

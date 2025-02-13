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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <daq.h>
#include <daq_dlt.h>
#include <daq_module_api.h>

#include "decode.h"

typedef enum
{
    PING_ACTION_PASS = 0,
    PING_ACTION_DROP,
    PING_ACTION_SPOOF,
    PING_ACTION_REPLACE,
    PING_ACTION_BLACKLIST,
    PING_ACTION_WHITELIST,
    PING_ACTION_CLONE,
    MAX_PING_ACTION = PING_ACTION_CLONE
} PingAction;

typedef struct _IPv4Addr
{
    struct _IPv4Addr *next;
    struct in_addr addr;
} IPv4Addr;

typedef struct _DAQTestModuleConfig
{
    struct _DAQTestModuleConfig *next;
    char *module_name;
    char **variables;
    unsigned num_variables;
    DAQ_Mode mode;
} DAQTestModuleConfig;

typedef struct _DAQTestConfig
{
    int verbosity;
    const char **module_paths;
    unsigned num_module_paths;
    DAQTestModuleConfig *module_configs;
    char *input;
    unsigned timeout;
    int snaplen;
    char *filter;
    unsigned batch_size;
    unsigned long packet_limit;
    unsigned long timeout_limit;
    unsigned long delay;
    DAQ_Verdict default_verdict;
    PingAction ping_action;
    IPv4Addr *ip_addrs;
    unsigned thread_count;
    int group_id;
    int user_id;
    bool list_and_exit;
    bool modify_opaque_value;
    bool performance_mode;
    bool dump_hex;
    bool dump_ascii;
    bool ignore_checksum_errors;
    bool explicit_thread_count;
} DAQTestConfig;

typedef struct _DAQTestThreadContext
{
    const DAQTestConfig *cfg;
    DAQ_Instance_h instance;
    DAQ_Msg_h *msgs;
    pthread_t tid;
    unsigned long packet_count;
    void *newconfig;
    void *oldconfig;
    volatile bool done;
    volatile bool exited;
} DAQTestThreadContext;

typedef struct _DAQTestPacket
{
    DAQ_Msg_h msg;
    const DAQTestThreadContext *ctxt;
    DecodeData dd;
} DAQTestPacket;


#ifdef USE_STATIC_MODULES
#ifdef BUILD_AFPACKET_MODULE
extern const DAQ_ModuleAPI_t afpacket_daq_module_data;
#endif
#ifdef BUILD_BPF_MODULE
extern const DAQ_ModuleAPI_t bpf_daq_module_data;
#endif
#ifdef BUILD_DIVERT_MODULE
extern const DAQ_ModuleAPI_t divert_daq_module_data;
#endif
#ifdef BUILD_DUMP_MODULE
extern const DAQ_ModuleAPI_t dump_daq_module_data;
#endif
#ifdef BUILD_FST_MODULE
extern const DAQ_ModuleAPI_t fst_daq_module_data;
#endif
#ifdef BUILD_NFQ_MODULE
extern const DAQ_ModuleAPI_t nfq_daq_module_data;
#endif
#ifdef BUILD_NETMAP_MODULE
extern const DAQ_ModuleAPI_t netmap_daq_module_data;
#endif
#ifdef BUILD_PCAP_MODULE
extern const DAQ_ModuleAPI_t pcap_daq_module_data;
#endif
#ifdef BUILD_NETMAP_MODULE
extern const DAQ_ModuleAPI_t netmap_daq_module_data;
#endif
#ifdef BUILD_SAVEFILE_MODULE
extern const DAQ_ModuleAPI_t savefile_daq_module_data;
#endif
#ifdef BUILD_TRACE_MODULE
extern const DAQ_ModuleAPI_t trace_daq_module_data;
#endif

static DAQ_Module_h static_modules[] =
{
#ifdef BUILD_AFPACKET_MODULE
    &afpacket_daq_module_data,
#endif
#ifdef BUILD_BPF_MODULE
    &bpf_daq_module_data,
#endif
#ifdef BUILD_DIVERT_MODULE
    &divert_daq_module_data,
#endif
#ifdef BUILD_DUMP_MODULE
    &dump_daq_module_data,
#endif
#ifdef BUILD_FST_MODULE
    &fst_daq_module_data,
#endif
#ifdef BUILD_NFQ_MODULE
    &nfq_daq_module_data,
#endif
#ifdef BUILD_PCAP_MODULE
    &pcap_daq_module_data,
#endif
#ifdef BUILD_NETMAP_MODULE
    &netmap_daq_module_data,
#endif
#ifdef BUILD_SAVEFILE_MODULE
    &savefile_daq_module_data,
#endif
#ifdef BUILD_TRACE_MODULE
    &trace_daq_module_data,
#endif
    NULL
};
#endif

static uint8_t normal_ping_data[IP_MAXPACKET];
static uint8_t fake_ping_data[IP_MAXPACKET];
static uint8_t local_mac_addr[ETHER_ADDR_LEN];

static volatile sig_atomic_t pending_signal = 0;
static int dlt;

const char *ping_action_strings[MAX_PING_ACTION+1] =
{
    "Pass", "Block", "Spoof", "Replace", "Blacklist", "Whitelist", "Clone"
};


static void handler(int sig)
{
    pending_signal = sig;
}

static void usage(void)
{
    printf("Usage: daqtest -d <daq_module> -i <input> [OPTION]...\n");
    printf("  -A <ip>           Specify an IP to respond to ARPs on (may be specified multiple times)\n");
    printf("  -b <num>          Specify the number of messages to request per receive call (default = 16)\n");
    printf("  -c <num>          Maximum number of packets to acquire (default = 0, <= 0 is unlimited)\n");
    printf("  -C <key[=value]>  Set a DAQ configuration variable key/value pair\n");
    printf("  -D <delay>        Specify a millisecond delay to be added to each packet processed\n");
    printf("  -f <bpf>          Specify the Berkley Packet Filter string to use for filtering\n");
    printf("  -g <groupname>    Run as the specified group after initialization (accepts GID)\n");
    printf("  -h                Display this usage text and exit\n");
    printf("  -k                Ignore checksum errors during protocol decoding\n");
    printf("  -l                Print a list of modules found and exit\n");
    printf("  -m <path>         Specify a direcotyr path to search for modules (may be specified multiple times)\n");
    printf("  -M <mode>         Specify the mode (passive (default), inline, read-file)\n");
    printf("  -O                Enable modifying the flow's opaque value on each packet\n");
    printf("  -p                Enable performance testing mode - auto-PASS and no decoding\n");
    printf("  -P <action>       Specify the action to perform when a ping is received (none (default), block, spoof, replace, blacklist, whitelist, clone)\n");
    printf("  -s <len>          Specify the capture length in bytes (default = 1518)\n");
    printf("  -t <num>          Specify the receive timeout in milliseconds (default = 0, 0 is unlimited)\n");
    printf("  -T <num>          Maximum number of receive timeouts to encounter before exiting (default = 0, 0 is unlimited)\n");
    printf("  -u <username>     Run as the specified user after initialization (accepts UID)\n");
    printf("  -v                Increase the verbosity level of the DAQ library (may be specified multiple times)\n");
    printf("  -V <verdict>      Specify a default verdict to render on packets (pass (default), block, blacklist, whitelist)\n");
    printf("  -x                Dump message data in hex\n");
    printf("  -X                Dump message data in hex and ASCII\n");
    printf("  -z <num>          Specify the number of packet threads to run (default = 1)\n");
}

static void print_mac(const uint8_t *addr)
{
    printf("%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

#define HEXDUMP_BYTES_PER_LINE 16
static void hexdump(const uint8_t *data, unsigned len, bool ascii)
{
    char text[HEXDUMP_BYTES_PER_LINE + 1];
    unsigned i = 0;

    printf("\n");
    while (i < len)
    {
        if (i % 2 == 0)
            printf(" ");
        printf("%02x", data[i]);
        if (ascii)
            text[i % HEXDUMP_BYTES_PER_LINE] = isprint(data[i]) ? data[i] : '.';
        i++;
        if (i % HEXDUMP_BYTES_PER_LINE == 0 || i == len)
        {
            if (ascii)
            {
                text[(i - 1) % HEXDUMP_BYTES_PER_LINE] = '\0';
                while (i % HEXDUMP_BYTES_PER_LINE != 0)
                {
                    printf("%*s", (i % 2) ? 3 : 2, "");
                    i++;
                }
                printf("  %s", text);
            }
            printf("\n");
        }
    }
    printf("\n");
}

static void initialize_static_data(void)
{
    char c;
    unsigned i;

    for (c = 0, i = 0; i < IP_MAXPACKET; c++, i++)
    {
        normal_ping_data[i] = c;
        fake_ping_data[i] = 'A';
    }

    srand(time(NULL) + getpid());   /* seed the RNG */
    for (i = 0; i < sizeof(local_mac_addr); i++)
        local_mac_addr[i] = (uint8_t) rand();
    local_mac_addr[0] &= 0xfe;    /* clear multicast bit */
    local_mac_addr[0] |= 0x02;    /* set local assignment bit (IEEE802) */
}

static int replace_icmp_data(DAQTestPacket *dtp)
{
    IcmpHdr *icmp;
    uint8_t *data;
    size_t dlen;
    int offset;
    int modified = 0;

    icmp = (IcmpHdr *) dtp->dd.icmp;
    icmp->checksum = 0;

    dlen = ntohs(dtp->dd.ip->tot_len) - sizeof(IpHdr) - sizeof(IcmpHdr);
    data = (uint8_t *) icmp + sizeof(IcmpHdr);
    offset = 0;
    if (dlen > sizeof(struct timeval))
    {
        printf("Accounting for ping timing data (%zu bytes).\n", sizeof(struct timeval));
        offset = sizeof(struct timeval);
        data += offset;
        dlen -= offset;
    }

    if (memcmp(data, normal_ping_data + offset, dlen) == 0)
    {
        printf("Replacing the ping request padding.\n");
        memcpy(data, fake_ping_data + offset, dlen);
        modified = 1;
    }
    else if (memcmp(data, fake_ping_data + offset, dlen) == 0)
    {
        printf("Replacing the ping reply padding.\n");
        memcpy(data, normal_ping_data + offset, dlen);
        modified = 1;
    }

    if (modified)
    {
        icmp->checksum = 0;
        struct cksum_vec vec = { (const uint16_t *) icmp, ntohs(dtp->dd.ip->tot_len) - sizeof(IpHdr) };
        icmp->checksum = in_cksum_vec(&vec, 1);
    }

    return modified;
}

static uint8_t *forge_etharp_reply(DAQTestPacket *dtp, const uint8_t *mac_addr)
{
    const uint8_t *request = daq_msg_get_data(dtp->msg);
    uint8_t *reply;
    const EthHdr *eth_request;
    EthHdr *eth_reply;
    const EthArp *etharp_request;
    EthArp *etharp_reply;
    size_t arphdr_offset;

    arphdr_offset = sizeof(*dtp->dd.eth) + dtp->dd.vlan_tags * sizeof(VlanTagHdr);
    reply = calloc(arphdr_offset + sizeof(EthArp), sizeof(uint8_t));

    /* Set up the ethernet header... */
    eth_request = dtp->dd.eth;
    eth_reply = (EthHdr *) reply;
    memcpy(eth_reply->ether_dhost, eth_request->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_reply->ether_shost, mac_addr, ETHER_ADDR_LEN);
    memcpy(reply + ETHER_ADDR_LEN * 2, request + ETHER_ADDR_LEN * 2, arphdr_offset - ETHER_ADDR_LEN * 2);

    /* Now the ARP header... */
    etharp_request = (const EthArp *) dtp->dd.arp;
    etharp_reply = (EthArp *) (reply + arphdr_offset);
    memcpy(&etharp_reply->ea_hdr, &etharp_request->ea_hdr, sizeof(EthArpHdr));
    etharp_reply->ea_hdr.ar_op = htons(ARPOP_REPLY);

    /* Finally, the ethernet ARP reply... */
    memcpy(etharp_reply->arp_sha, mac_addr, ETHER_ADDR_LEN);
    memcpy(etharp_reply->arp_spa, etharp_request->arp_tpa, 4);
    memcpy(etharp_reply->arp_tha, etharp_request->arp_sha, ETHER_ADDR_LEN);
    memcpy(etharp_reply->arp_tpa, etharp_request->arp_spa, 4);

    return reply;
}

static size_t forge_icmp_reply(DAQTestPacket *dtp, uint8_t **reply_ptr)
{
    const uint8_t *request = daq_msg_get_data(dtp->msg);
    uint8_t *reply;
    size_t iphdr_offset;
    size_t reply_len;

    if (dtp->dd.eth)
    {
        iphdr_offset = sizeof(*dtp->dd.eth) + dtp->dd.vlan_tags * sizeof(VlanTagHdr);
        reply_len = iphdr_offset + ntohs(dtp->dd.ip->tot_len);
        reply = calloc(reply_len, sizeof(uint8_t));

        /* Set up the ethernet header... */
        const EthHdr *eth_request = dtp->dd.eth;
        EthHdr *eth_reply = (EthHdr *) reply;
        memcpy(eth_reply->ether_dhost, eth_request->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_reply->ether_shost, eth_request->ether_dhost, ETHER_ADDR_LEN);
        memcpy(reply + ETHER_ADDR_LEN * 2, request + ETHER_ADDR_LEN * 2, iphdr_offset - ETHER_ADDR_LEN * 2);
    }
    else
    {
        iphdr_offset = 0;
        reply_len = ntohs(dtp->dd.ip->tot_len);
        reply = calloc(reply_len, sizeof(uint8_t));
    }

    /* Now the IP header... */
    const IpHdr *ip_request = dtp->dd.ip;
    IpHdr *ip_reply = (IpHdr *) (reply + iphdr_offset);
    ip_reply->ihl = ip_request->ihl;
    ip_reply->version = ip_request->version;
    ip_reply->tos = ip_request->tos;
    ip_reply->tot_len = ip_request->tot_len;
    ip_reply->id = ip_request->id;
    ip_reply->frag_off = ip_request->frag_off;
    ip_reply->ttl = ip_request->ttl;
    ip_reply->protocol = ip_request->protocol;
    ip_reply->check = 0;
    ip_reply->saddr = ip_request->daddr;
    ip_reply->daddr = ip_request->saddr;
    struct cksum_vec vec = { (const uint16_t *) ip_reply, ip_reply->ihl * 4 };
    ip_reply->check = in_cksum_vec(&vec, 1);

    /* And the ICMP header... */
    const IcmpHdr *icmp_request = dtp->dd.icmp;
    IcmpHdr *icmp_reply = (IcmpHdr *) (reply + iphdr_offset + sizeof(IpHdr));
    icmp_reply->type = ICMP_ECHOREPLY;
    icmp_reply->code = 0;
    icmp_reply->checksum = 0;
    icmp_reply->un.echo.id = icmp_request->un.echo.id;
    icmp_reply->un.echo.sequence = icmp_request->un.echo.sequence;

    /* Copy the ICMP padding... */
    uint32_t dlen = ntohs(ip_request->tot_len) - sizeof(IpHdr) - sizeof(IcmpHdr);
    memcpy(icmp_reply + 1, icmp_request + 1, dlen);

    /* Last, but not least, checksum the ICMP packet */
    vec.addr = (uint16_t *) icmp_reply;
    vec.len = ntohs(ip_request->tot_len) - sizeof(IpHdr);
    icmp_reply->checksum = in_cksum_vec(&vec, 1);

    *reply_ptr = reply;

    return reply_len;
}

static DAQ_Verdict process_ping(DAQTestPacket *dtp)
{
    int rc;

    switch (dtp->ctxt->cfg->ping_action)
    {
        case PING_ACTION_PASS:
            break;

        case PING_ACTION_SPOOF:
            if (dtp->dd.icmp->type == ICMP_ECHO)
            {
                uint8_t *reply;
                size_t reply_len;

                reply_len = forge_icmp_reply(dtp, &reply);
                printf("Injecting forged ICMP reply back to source! (%zu bytes)\n", reply_len);
                rc = daq_instance_inject_relative(dtp->ctxt->instance, dtp->msg, reply, reply_len, 1);
                if (rc == DAQ_ERROR_NOTSUP)
                    printf("This module does not support packet injection.\n");
                else if (rc != DAQ_SUCCESS)
                    printf("Failed to inject ICMP reply: %s\n", daq_instance_get_error(dtp->ctxt->instance));
                free(reply);
                return DAQ_VERDICT_BLOCK;
            }
            break;

        case PING_ACTION_DROP:
            printf("Blocking the ping packet.\n");
            return DAQ_VERDICT_BLOCK;

        case PING_ACTION_REPLACE:
            replace_icmp_data(dtp);
            return DAQ_VERDICT_REPLACE;

        case PING_ACTION_BLACKLIST:
            printf("Blacklisting the ping's flow.\n");
            return DAQ_VERDICT_BLACKLIST;

        case PING_ACTION_WHITELIST:
            printf("Whitelisting the ping's flow.\n");
            return DAQ_VERDICT_WHITELIST;

        case PING_ACTION_CLONE:
            printf("Injecting cloned ICMP packet.\n");
            rc = daq_instance_inject_relative(dtp->ctxt->instance, dtp->msg, daq_msg_get_data(dtp->msg),
                    daq_msg_get_data_len(dtp->msg), 0);
            if (rc == DAQ_ERROR_NOTSUP)
                printf("This module does not support packet injection.\n");
            else if (rc != DAQ_SUCCESS)
                printf("Failed to inject cloned ICMP packet: %s\n", daq_instance_get_error(dtp->ctxt->instance));
            printf("Blocking the original ICMP packet.\n");
            return DAQ_VERDICT_BLOCK;
    }
    return DAQ_VERDICT_PASS;
}

static DAQ_Verdict process_icmp(DAQTestPacket *dtp)
{
    unsigned dlen;

    dlen = ntohs(dtp->dd.ip->tot_len) - sizeof(IpHdr) - sizeof(IcmpHdr);
    printf("  ICMP: Type %hhu  Code %hhu  Checksum %hu%s  (%u bytes of data)\n",
           dtp->dd.icmp->type, dtp->dd.icmp->code, dtp->dd.icmp->checksum,
           !dtp->dd.decoded_data.flags.bits.l4_checksum ? " (incorrect)" : "", dlen);
    if (dtp->dd.icmp->type == ICMP_ECHO || dtp->dd.icmp->type == ICMP_ECHOREPLY)
    {
        printf("   Echo: ID %hu  Sequence %hu\n",
               ntohs(dtp->dd.icmp->un.echo.id), ntohs(dtp->dd.icmp->un.echo.sequence));
        return process_ping(dtp);
    }

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_icmp6(DAQTestPacket *dtp)
{
    unsigned dlen;

    dlen = ntohs(dtp->dd.ip6->ip6_plen) - sizeof(Ip6Hdr) - sizeof(Icmp6Hdr);
    printf("  ICMPv6: Type %hhu  Code %hhu  Checksum %hu%s  (%u bytes of data)\n",
           dtp->dd.icmp6->icmp6_type, dtp->dd.icmp6->icmp6_code, dtp->dd.icmp6->icmp6_cksum,
           !dtp->dd.decoded_data.flags.bits.l4_checksum ? " (incorrect)" : "", dlen);
    if (dtp->dd.icmp6->icmp6_type == ICMP6_ECHO_REQUEST || dtp->dd.icmp6->icmp6_type == ICMP6_ECHO_REPLY)
    {
        printf("   Echo: ID %hu  Sequence %hu\n",
               ntohs(dtp->dd.icmp6->icmp6_id), ntohs(dtp->dd.icmp6->icmp6_seq));
        //return process_ping(dtp);
    }

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_udp(DAQTestPacket *dtp)
{
    printf("  UDP: %hu -> %hu  Checksum %hu%s  (%hu bytes of data)\n",
           ntohs(dtp->dd.udp->uh_sport), ntohs(dtp->dd.udp->uh_dport), ntohs(dtp->dd.udp->uh_sum),
           !dtp->dd.decoded_data.flags.bits.l4_checksum ? " (incorrect)" : "", ntohs(dtp->dd.udp->uh_ulen));

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_tcp(DAQTestPacket *dtp)
{
    unsigned dlen;

    if (dtp->dd.ip)
        dlen = ntohs(dtp->dd.ip->tot_len) - (dtp->dd.ip->ihl * 4) - (dtp->dd.tcp->th_off * 4);
    else
        dlen = ntohs(dtp->dd.ip6->ip6_plen) - (dtp->dd.tcp->th_off * 4);
    printf("  TCP: %hu -> %hu  Checksum %hu%s  (%u bytes of data)\n",
           ntohs(dtp->dd.tcp->th_sport), ntohs(dtp->dd.tcp->th_dport), ntohs(dtp->dd.tcp->th_sum),
           !dtp->dd.decoded_data.flags.bits.l4_checksum ? " (incorrect)" : "", dlen);

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_arp(DAQTestPacket *dtp)
{
    const EthArp *etharp;
    struct in_addr addr;
    IPv4Addr *ip;
    uint8_t *reply;
    size_t reply_len;

    printf(" ARP: Hardware Type %hu (%hhu)  Protocol Type %.4hX (%hhu)  Operation %hu\n",
            ntohs(dtp->dd.arp->ar_hrd), dtp->dd.arp->ar_hln, ntohs(dtp->dd.arp->ar_pro),
            dtp->dd.arp->ar_pln, ntohs(dtp->dd.arp->ar_op));

    if (ntohs(dtp->dd.arp->ar_hrd) != ARPHRD_ETHER)
        return dtp->ctxt->cfg->default_verdict;

    etharp = (const EthArp *) dtp->dd.arp;

    printf("  Sender: ");
    print_mac(etharp->arp_sha);
    memcpy(&addr.s_addr, etharp->arp_spa, 4);
    printf(" (%s)\n", inet_ntoa(addr));

    printf("  Target: ");
    print_mac(etharp->arp_tha);
    memcpy(&addr.s_addr, etharp->arp_tpa, 4);
    printf(" (%s)\n", inet_ntoa(addr));

    if (ntohs(dtp->dd.arp->ar_op) != ARPOP_REQUEST || ntohs(dtp->dd.arp->ar_pro) != ETYPE_IP)
        return dtp->ctxt->cfg->default_verdict;

    for (ip = dtp->ctxt->cfg->ip_addrs; ip; ip = ip->next)
    {
        if (!memcmp(&addr, &ip->addr, sizeof(addr)))
            break;
    }

    /* Only perform Ethernet ARP spoofing when in ping spoofing mode and passive mode. */
    //if (!ip && (dtp->ctxt->cfg->ping_action != PING_ACTION_SPOOF || dtp->ctxt->cfg->mode != DAQ_MODE_PASSIVE))
    if (!ip || dtp->ctxt->cfg->ping_action != PING_ACTION_SPOOF)
       return dtp->ctxt->cfg->default_verdict;

    reply = forge_etharp_reply(dtp, local_mac_addr);
    reply_len = sizeof(*dtp->dd.eth) + dtp->dd.vlan_tags * sizeof(VlanTagHdr) + sizeof(EthArp);
    printf("Injecting forged Ethernet ARP reply back to source (%zu bytes)!\n", reply_len);
    if (daq_instance_inject_relative(dtp->ctxt->instance, dtp->msg, reply, reply_len, 1))
        printf("Failed to inject ARP reply: %s\n", daq_instance_get_error(dtp->ctxt->instance));
    free(reply);

    return DAQ_VERDICT_BLOCK;
}

static DAQ_Verdict process_ip6(DAQTestPacket *dtp)
{
    char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &dtp->dd.ip6->ip6_src, src_addr_str, sizeof(src_addr_str));
    inet_ntop(AF_INET6, &dtp->dd.ip6->ip6_dst, dst_addr_str, sizeof(dst_addr_str));

    uint8_t next_hdr = dtp->dd.ip6->ip6_nxt;
    if (next_hdr == IPPROTO_FRAGMENT)
    {
        const Ip6Frag *frag = (const Ip6Frag *) (dtp->dd.ip6 + 1);
        next_hdr = frag->ip6f_nxt;
    }

    printf(" IP6: %s -> %s (%hu bytes) (next header: %hhu)\n",
            src_addr_str, dst_addr_str, ntohs(dtp->dd.ip6->ip6_plen), next_hdr);

    switch (next_hdr)
    {
        case IPPROTO_TCP:
            return process_tcp(dtp);
        case IPPROTO_UDP:
            return process_udp(dtp);
        case IPPROTO_ICMPV6:
            return process_icmp6(dtp);
    }

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_ip(DAQTestPacket *dtp)
{
    struct in_addr addr;
    char src_addr_str[INET_ADDRSTRLEN], dst_addr_str[INET_ADDRSTRLEN];

    /* Print source and destination IP addresses. */
    addr.s_addr = dtp->dd.ip->saddr;
    inet_ntop(AF_INET, &addr, src_addr_str, sizeof(src_addr_str));
    addr.s_addr = dtp->dd.ip->daddr;
    inet_ntop(AF_INET, &addr, dst_addr_str, sizeof(dst_addr_str));
    printf(" IP: %s -> %s (%hu bytes) (checksum: %hu%s) (protocol: %hhu)\n",
            src_addr_str, dst_addr_str, ntohs(dtp->dd.ip->tot_len), dtp->dd.ip->check,
            !dtp->dd.decoded_data.flags.bits.l3_checksum ? " (incorrect)" : "", dtp->dd.ip->protocol);

    switch (dtp->dd.ip->protocol)
    {
        case IPPROTO_TCP:
            return process_tcp(dtp);
        case IPPROTO_UDP:
            return process_udp(dtp);
        case IPPROTO_ICMP:
            return process_icmp(dtp);
    }

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_eth(DAQTestPacket *dtp)
{
    printf("MAC: ");
    print_mac(dtp->dd.eth->ether_shost);
    printf(" -> ");
    print_mac(dtp->dd.eth->ether_dhost);
    printf(" (%.4hX) (%u bytes)\n", ntohs(dtp->dd.eth->ether_type), daq_msg_get_data_len(dtp->msg));
    if (dtp->dd.vlan_tags > 0)
    {
        uint16_t ether_type;
        uint16_t offset;

        printf(" VLAN Tags (%hu):", dtp->dd.vlan_tags);
        ether_type = ntohs(dtp->dd.eth->ether_type);
        offset = sizeof(*dtp->dd.eth);
        while (is_vlan_ethertype(ether_type))
        {
            const VlanTagHdr *vlan;

            vlan = (const VlanTagHdr *) (daq_msg_get_data(dtp->msg) + offset);
            ether_type = ntohs(vlan->vth_proto);
            offset += sizeof(*vlan);
            printf(" %hu/%hu", VTH_VLAN(vlan), VTH_PRIORITY(vlan));
        }
        printf("\n");
    }
    if (dtp->dd.arp)
        return process_arp(dtp);

    if (dtp->dd.ip)
        return process_ip(dtp);

    if (dtp->dd.ip6)
        return process_ip6(dtp);

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_packet(DAQTestPacket *dtp)
{
    switch (dlt)
    {
        case DLT_EN10MB:
            if (dtp->dd.eth)
                return process_eth(dtp);
            break;

        case DLT_RAW:
            if (dtp->dd.ip)
                return process_ip(dtp);
            if (dtp->dd.ip6)
                return process_ip6(dtp);
            break;

        case DLT_IPV4:
            if (dtp->dd.ip)
                return process_ip(dtp);
            break;

        case DLT_IPV6:
            if (dtp->dd.ip6)
                return process_ip6(dtp);
            break;

        default:
            printf("Unhandled datalink type: %d!\n", dlt);
    }

    return dtp->ctxt->cfg->default_verdict;
}

static bool decode_packet(const uint8_t *packet, uint32_t len, DecodeData *dd)
{
    switch (dlt)
    {
        case DLT_EN10MB:
            return decode_eth(packet, len, dd);

        case DLT_RAW:
            return decode_raw(packet, len, dd);

        case DLT_IPV4:
            return decode_ip(packet, len, dd);

        case DLT_IPV6:
            return decode_ip6(packet, len, dd);

        default:
            printf("Unhandled datalink type: %d!\n", dlt);
    }
    return false;
}

static DAQ_Verdict handle_packet_message(DAQTestThreadContext *ctxt, DAQ_Msg_h msg)
{
    const DAQ_PktHdr_t *hdr = daq_msg_get_pkthdr(msg);
    const uint8_t *data = daq_msg_get_data(msg);
    const uint32_t data_len = daq_msg_get_data_len(msg);
    const DAQTestConfig *cfg = ctxt->cfg;

    ctxt->packet_count++;

    if (cfg->delay)
        usleep(cfg->delay * 1000);

    if (cfg->performance_mode)
        return cfg->default_verdict;

    printf("\nPacket %" PRIu64 ": Size = %u/%u, Ingress = %d (Group = %hd), Egress = %d (Group = %hd), Addr Space ID = %u",
            ctxt->packet_count, data_len, hdr->pktlen, hdr->ingress_index, hdr->ingress_group,
            hdr->egress_index, hdr->egress_group, hdr->address_space_id);
    if (hdr->flags & DAQ_PKT_FLAG_OPAQUE_IS_VALID)
        printf(", Opaque = %u", hdr->opaque);
    if (hdr->flags & DAQ_PKT_FLAG_FLOWID_IS_VALID)
        printf(", Flow ID = %u", hdr->flow_id);
    printf("\n");

    if (hdr->flags)
    {
        printf("Flags (0x%X): ", hdr->flags);
        if (hdr->flags & DAQ_PKT_FLAG_OPAQUE_IS_VALID)
            printf("OPAQUE_IS_VALID ");
        if (hdr->flags & DAQ_PKT_FLAG_NOT_FORWARDING)
            printf("NOT_FORWARDING ");
        if (hdr->flags & DAQ_PKT_FLAG_PRE_ROUTING)
            printf("PRE_ROUTING ");
        if (hdr->flags & DAQ_PKT_FLAG_IGNORE_VLAN)
            printf("IGNORE_VLAN ");
        if (hdr->flags & DAQ_PKT_FLAG_FLOWID_IS_VALID)
            printf("FLOWID_IS_VALID ");
        if (hdr->flags & DAQ_PKT_FLAG_LOCALLY_DESTINED)
            printf("LOCALLY_DESTINED ");
        if (hdr->flags & DAQ_PKT_FLAG_LOCALLY_ORIGINATED)
            printf("LOCALLY_ORIGINATED ");
        if (hdr->flags & DAQ_PKT_FLAG_SCRUBBED_TCP_OPTS)
            printf("SCRUBBED_TCP_OPTS ");
        if (hdr->flags & DAQ_PKT_FLAG_HA_STATE_AVAIL)
            printf("HA_STATE_AVAIL ");
        if (hdr->flags & DAQ_PKT_FLAG_ERROR_PACKET)
            printf("ERROR_PACKET ");
        if (hdr->flags & DAQ_PKT_FLAG_TRACE_ENABLED)
            printf("TRACE_ENABLED ");
        if (hdr->flags & DAQ_PKT_FLAG_SIMULATED)
            printf("SIMULATED ");
        if (hdr->flags & DAQ_PKT_FLAG_NEW_FLOW)
            printf("NEW_FLOW ");
        if (hdr->flags & DAQ_PKT_FLAG_REV_FLOW)
            printf("REV_FLOW ");
        if (hdr->flags & DAQ_PKT_FLAG_DEBUG_ENABLED)
            printf("DEBUG_ENABLED ");
        if (hdr->flags & DAQ_PKT_FLAG_SIGNIFICANT_GROUPS)
            printf("SIGNIFICANT_GROUPS ");
        printf("\n");
    }

    const DAQ_NAPTInfo_t *napti = (const DAQ_NAPTInfo_t *) daq_msg_get_meta(msg, DAQ_PKT_META_NAPT_INFO);
    if (napti)
    {
        char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN];
        uint16_t src_port, dst_port;

        inet_ntop(daq_napt_info_src_addr_family(napti), &napti->src_addr, src_addr_str, sizeof(src_addr_str));
        src_port = ntohs(napti->src_port);
        inet_ntop(daq_napt_info_dst_addr_family(napti), &napti->dst_addr, dst_addr_str, sizeof(dst_addr_str));
        dst_port = ntohs(napti->dst_port);

        printf("NAPT: Layer %hhu: %s : %hu -> %s : %hu\n", napti->ip_layer, src_addr_str, src_port, dst_addr_str, dst_port);
    }

    const DAQ_PktDecodeData_t *pdd = (const DAQ_PktDecodeData_t *) daq_msg_get_meta(msg, DAQ_PKT_META_DECODE_DATA);
    if (pdd)
    {
        printf("Decode Data:\n");
        printf("  Offsets: L2 = %hu, L3 = %hu, L4 = %hu, PL = %hu, CO = %hu\n", pdd->l2_offset,
                pdd->l3_offset, pdd->l4_offset, pdd->payload_offset, pdd->checksum_offset);
        printf("  Flags:");
        if (pdd->flags.bits.l2)
            printf(" L2");
        if (pdd->flags.bits.l2_checksum)
            printf(" L2_CKSUM");
        if (pdd->flags.bits.l3)
            printf(" L3");
        if (pdd->flags.bits.l3_checksum)
            printf(" L3_CKSUM");
        if (pdd->flags.bits.l4)
            printf(" L4");
        if (pdd->flags.bits.l4_checksum)
            printf(" L4_CKSUM");
        if (pdd->flags.bits.checksum_error)
            printf(" CKSUM_ERR");
        if (pdd->flags.bits.vlan)
            printf(" VLAN");
        if (pdd->flags.bits.vlan_qinq)
            printf(" VLAN_QINQ");
        if (pdd->flags.bits.ethernet)
            printf(" ETH");
        if (pdd->flags.bits.ipv4)
            printf(" IPv4");
        if (pdd->flags.bits.ipv6)
            printf(" IPv6");
        if (pdd->flags.bits.udp)
            printf(" UDP");
        if (pdd->flags.bits.tcp)
            printf(" TCP");
        if (pdd->flags.bits.icmp)
            printf(" ICMP");
        if (pdd->flags.bits.tcp_opt_mss)
            printf(" TCP_OPT_MSS");
        if (pdd->flags.bits.tcp_opt_ws)
            printf(" TCP_OPT_WS");
        if (pdd->flags.bits.tcp_opt_ts)
            printf(" TCP_OPT_TS");
        printf("\n");
    }

    const DAQ_PktTcpAckData_t *ptad = (const DAQ_PktTcpAckData_t *) daq_msg_get_meta(msg, DAQ_PKT_META_TCP_ACK_DATA);
    if (ptad)
        printf("TCP ACK Data: SN = %u, WS = %hu\n", ptad->tcp_ack_seq_num, ptad->tcp_window_size);

    if (cfg->dump_hex)
        hexdump(data, data_len, cfg->dump_ascii);

    if (cfg->modify_opaque_value)
    {
        DIOCTL_SetFlowOpaque d_sfo;
        d_sfo.msg = msg;
        d_sfo.value = ctxt->packet_count;
        daq_instance_ioctl(ctxt->instance, DIOCTL_SET_FLOW_OPAQUE, &d_sfo, sizeof(d_sfo));
    }

    DAQTestPacket dtp;
    memset(&dtp, 0, sizeof(dtp));
    dtp.msg = msg;
    dtp.ctxt = ctxt;
    decode_data_init(&dtp.dd, data, cfg->ignore_checksum_errors);
    if (!decode_packet(data, data_len, &dtp.dd))
        return ctxt->cfg->default_verdict;

    return process_packet(&dtp);
}

static void handle_flow_stats_message(DAQTestThreadContext *ctxt, DAQ_Msg_h msg)
{
    const DAQTestConfig *cfg = ctxt->cfg;

    if (cfg->performance_mode)
        return;

    const DAQ_FlowStats_t *stats = (const DAQ_FlowStats_t *) daq_msg_get_hdr(msg);
    char addr_str[INET6_ADDRSTRLEN];
    const struct in6_addr* tmpIp;
    struct tm tm;
    char timestr[64];

    printf("\nReceived %s message.\n", msg->type == DAQ_MSG_TYPE_SOF ? "SoF" : "EoF");

    if (stats->ingress_intf != DAQ_PKTHDR_UNKNOWN || stats->ingress_group != DAQ_PKTHDR_UNKNOWN)
    {
        printf("  Ingress:\n");
        if (stats->ingress_intf != DAQ_PKTHDR_UNKNOWN)
            printf("    Interface: %d\n", stats->ingress_intf);
        if (stats->ingress_group != DAQ_PKTHDR_UNKNOWN)
            printf("    Group: %hd\n", stats->ingress_group);
    }
    if (stats->egress_intf != DAQ_PKTHDR_UNKNOWN || stats->egress_group != DAQ_PKTHDR_UNKNOWN)
    {
        printf("  Egress:\n");
        if (stats->egress_intf != DAQ_PKTHDR_UNKNOWN)
            printf("    Interface: %d\n", stats->egress_intf);
        if (stats->egress_group != DAQ_PKTHDR_UNKNOWN)
            printf("    Group: %hd\n", stats->egress_group);
    }
    printf("  Protocol: %hhu\n", stats->protocol);
    if (stats->vlan_tag != 0)
        printf("  VLAN: %hu\n", stats->vlan_tag);
    if (stats->opaque != 0)
        printf("  Opaque: %u\n", stats->opaque);
    if (stats->flags)
    {
        printf("  Flags (0x%X): ", stats->flags);
        if (stats->flags & DAQ_FS_FLAG_SIGNIFICANT_GROUPS)
            printf("SIGNIFICANT_GROUPS ");
        printf("\n");
    }
    printf("  Initiator:\n");
    tmpIp = (const struct in6_addr*)stats->initiator_ip;
    if (tmpIp->s6_addr32[0] || tmpIp->s6_addr32[1] || tmpIp->s6_addr16[4] || tmpIp->s6_addr16[5] != 0xFFFF)
        inet_ntop(AF_INET6, tmpIp, addr_str, sizeof(addr_str));
    else
        inet_ntop(AF_INET, &tmpIp->s6_addr32[3], addr_str, sizeof(addr_str));
    printf("    IP: %s", addr_str);
    if (stats->protocol == IPPROTO_UDP || stats->protocol == IPPROTO_TCP
            || stats->protocol == IPPROTO_ICMP || stats->protocol == IPPROTO_ICMPV6)
        printf(":%d", ntohs(stats->initiator_port));
    printf("\n");
    if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("    Sent: %" PRIu64 " bytes (%" PRIu64 " packets)\n", stats->initiator_bytes, stats->initiator_pkts);
    printf("  Responder:\n");
    tmpIp = (const struct in6_addr*)stats->responder_ip;
    if (tmpIp->s6_addr32[0] || tmpIp->s6_addr32[1] || tmpIp->s6_addr16[4] || tmpIp->s6_addr16[5] != 0xFFFF)
        inet_ntop(AF_INET6, tmpIp, addr_str, sizeof(addr_str));
    else
        inet_ntop(AF_INET, &tmpIp->s6_addr32[3], addr_str, sizeof(addr_str));
    printf("    IP: %s", addr_str);
    if (stats->protocol == IPPROTO_UDP || stats->protocol == IPPROTO_TCP
            || stats->protocol == IPPROTO_ICMP || stats->protocol == IPPROTO_ICMPV6)
        printf(":%d", ntohs(stats->responder_port));
    printf("\n");
    if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("    Sent: %" PRIu64 " bytes (%" PRIu64 " packets)\n", stats->responder_bytes, stats->responder_pkts);

    gmtime_r(&stats->sof_timestamp.tv_sec, &tm);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm);
    printf("  First Packet: %s.%06lu\n", timestr, (unsigned long)stats->sof_timestamp.tv_usec);
    if (msg->type == DAQ_MSG_TYPE_EOF)
    {
        gmtime_r(&stats->eof_timestamp.tv_sec, &tm);
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm);
        printf("  Last Packet:  %s.%06lu\n", timestr, (unsigned long)stats->eof_timestamp.tv_usec);
    }
}

static void print_daq_stats(DAQ_Stats_t *stats)
{
    printf("*DAQ Module Statistics*\n");
    printf("  Hardware Packets Received:  %" PRIu64 "\n", stats->hw_packets_received);
    printf("  Hardware Packets Dropped:   %" PRIu64 "\n", stats->hw_packets_dropped);
    printf("  Packets Received:   %" PRIu64 "\n", stats->packets_received);
    printf("  Packets Filtered:   %" PRIu64 "\n", stats->packets_filtered);
    printf("  Packets Passed:     %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_PASS]);
    printf("  Packets Replaced:   %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_REPLACE]);
    printf("  Packets Blocked:    %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_BLOCK]);
    printf("  Packets Injected:   %" PRIu64 "\n", stats->packets_injected);
    printf("  Flows Whitelisted:  %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_WHITELIST]);
    printf("  Flows Blacklisted:  %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_BLACKLIST]);
    printf("  Flows Ignored:      %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_IGNORE]);
}

static void print_daq_modules(void)
{
    DAQ_Module_h module = daq_modules_first();
    while (module)
    {
        printf("\n[%s]\n", daq_module_get_name(module));
        printf(" Version: %u\n", daq_module_get_version(module));
        printf(" Type: 0x%x\n", daq_module_get_type(module));

        const DAQ_VariableDesc_t *var_desc_table;
        int num_var_descs = daq_module_get_variable_descs(module, &var_desc_table);
        if (num_var_descs)
        {
            printf(" Variables:\n");
            for (int i = 0; i < num_var_descs; i++)
            {
                printf("  %s ", var_desc_table[i].name);
                if (var_desc_table[i].flags & DAQ_VAR_DESC_REQUIRES_ARGUMENT)
                    printf("<arg> ");
                else if (!(var_desc_table[i].flags & DAQ_VAR_DESC_FORBIDS_ARGUMENT))
                    printf("[arg] ");
                printf("- %s\n", var_desc_table[i].description);
            }
        }

        module = daq_modules_next();
    }
    printf("\n");
}

static DAQTestModuleConfig *daqtest_module_config_new(void)
{
    DAQTestModuleConfig *dtmc;

    dtmc = calloc(1, sizeof(DAQTestModuleConfig));
    if (!dtmc)
    {
        fprintf(stderr, "Failed to allocate a new DAQTest module configuration!\n\n");
        return NULL;
    }

    /* Some default values. */
    dtmc->mode = DAQ_MODE_PASSIVE;

    return dtmc;
}

static int gid_from_groupname(const char *name)
{
    struct group *grp;
    char *endptr;
    gid_t gid;

    if (!name || *name == '\0')
        return -1;

    /* Accept a numeric string and assume it's a GID. */
    gid = strtol(name, &endptr, 10);
    if (*endptr == '\0')
        return gid;

    grp = getgrnam(name);
    if (!grp)
        return -1;

    return grp->gr_gid;
}

static int uid_from_username(const char *name)
{
    struct passwd *pwd;
    char *endptr;
    uid_t uid;

    if (!name || *name == '\0')
        return -1;

    /* Accept a numeric string and assume it's a UID. */
    uid = strtol(name, &endptr, 10);
    if (*endptr == '\0')
        return uid;

    pwd = getpwnam(name);
    if (!pwd)
        return -1;

    return pwd->pw_uid;
}

static int parse_command_line(int argc, char *argv[], DAQTestConfig *cfg)
{
    DAQTestModuleConfig *dtmc;
    IPv4Addr *ip;
    const char *options = "A:b:c:C:d:D:f:g:hi:klm:M:OpP:s:t:T:u:vV:xXz:";
    char *endptr;
    int ch;

    /* Clear configuration and initialize to defaults. */
    memset(cfg, 0, sizeof(DAQTestConfig));
    cfg->snaplen = 1518;
    cfg->default_verdict = DAQ_VERDICT_PASS;
    cfg->ping_action = PING_ACTION_PASS;
    cfg->batch_size = 16;
    cfg->thread_count = 1;
    cfg->group_id = -1;
    cfg->user_id = -1;
    cfg->module_configs = daqtest_module_config_new();
    if (!cfg->module_configs)
        return -1;
    dtmc = cfg->module_configs;

    opterr = 0;
    while ((ch = getopt(argc, argv, options)) != -1)
    {
        switch (ch)
        {
            case 'A':
                ip = calloc(1, sizeof(*ip));
                if (!ip)
                {
                    fprintf(stderr, "Failed to allocate space for an IP address!\n\n");
                    return -1;
                }
                if (!inet_pton(AF_INET, optarg, &ip->addr))
                {
                    fprintf(stderr, "Invalid IP address specified: %s\n\n", optarg);
                    free(ip);
                    return -1;
                }
                ip->next = cfg->ip_addrs;
                cfg->ip_addrs = ip;
                break;

            case 'b':
                errno = 0;
                cfg->batch_size = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid batch size specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'c':
                errno = 0;
                cfg->packet_limit = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid packet limit specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'C':
                dtmc->num_variables++;
                dtmc->variables = realloc(dtmc->variables, dtmc->num_variables * sizeof(char *));
                if (!dtmc->variables)
                {
                    fprintf(stderr, "Failed to allocate space for a variable pointer!\n\n");
                    return -1;
                }
                dtmc->variables[dtmc->num_variables - 1] = optarg;
                break;

            case 'd':
                if (dtmc->module_name)
                {
                    /* Begin configuring a new module. */
                    dtmc->next = daqtest_module_config_new();
                    if (!dtmc->next)
                        return -1;
                    dtmc = dtmc->next;
                }
                dtmc->module_name = optarg;
                break;

            case 'D':
                errno = 0;
                cfg->delay = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid packet delay specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'f':
                cfg->filter = optarg;
                break;

            case 'g':
                cfg->group_id = gid_from_groupname(optarg);
                if (cfg->group_id == -1)
                {
                    fprintf(stderr, "Invalid group specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'h':
                usage();
                exit(0);

            case 'i':
                cfg->input = optarg;
                break;

            case 'k':
                cfg->ignore_checksum_errors = true;
                break;

            case 'l':
                cfg->list_and_exit = true;
                break;

            case 'm':
                cfg->num_module_paths++;
                cfg->module_paths = realloc(cfg->module_paths, (cfg->num_module_paths + 1) * sizeof(char *));
                if (!cfg->module_paths)
                {
                    fprintf(stderr, "Failed to allocate space for a module path pointer!\n\n");
                    return -1;
                }
                cfg->module_paths[cfg->num_module_paths - 1] = optarg;
                cfg->module_paths[cfg->num_module_paths] = NULL;
                break;

            case 'M':
                for (dtmc->mode = DAQ_MODE_PASSIVE; dtmc->mode < MAX_DAQ_MODE; dtmc->mode++)
                {
                    if (!strcmp(optarg, daq_mode_string(dtmc->mode)))
                        break;
                }
                if (dtmc->mode == MAX_DAQ_MODE)
                {
                    fprintf(stderr, "Invalid mode: %s!\n", optarg);
                    return -1;
                }
                break;

            case 'O':
                cfg->modify_opaque_value = true;
                break;

            case 'p':
                cfg->performance_mode = true;
                break;

            case 'P':
                if (!strcmp(optarg, "block"))
                    cfg->ping_action = PING_ACTION_DROP;
                else if (!strcmp(optarg, "spoof"))
                    cfg->ping_action = PING_ACTION_SPOOF;
                else if (!strcmp(optarg, "replace"))
                    cfg->ping_action = PING_ACTION_REPLACE;
                else if (!strcmp(optarg, "blacklist"))
                    cfg->ping_action = PING_ACTION_BLACKLIST;
                else if (!strcmp(optarg, "whitelist"))
                    cfg->ping_action = PING_ACTION_WHITELIST;
                else if (!strcmp(optarg, "clone"))
                    cfg->ping_action = PING_ACTION_CLONE;
                else
                {
                    fprintf(stderr, "Invalid ping argument specified (%s)!\n\n", optarg);
                    return -1;
                }
                break;

            case 's':
                errno = 0;
                cfg->snaplen = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid snap length specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 't':
                errno = 0;
                cfg->timeout = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid receive timeout specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'T':
                errno = 0;
                cfg->timeout_limit = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid receive timeout limit specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'u':
                cfg->user_id = uid_from_username(optarg);
                if (cfg->user_id == -1)
                {
                    fprintf(stderr, "Invalid user specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'v':
                cfg->verbosity++;
                break;

            case 'V':
                if (!strcmp(optarg, "pass"))
                    cfg->default_verdict = DAQ_VERDICT_PASS;
                else if (!strcmp(optarg, "block"))
                    cfg->default_verdict = DAQ_VERDICT_BLOCK;
                else if (!strcmp(optarg, "blacklist"))
                    cfg->default_verdict = DAQ_VERDICT_BLACKLIST;
                else if (!strcmp(optarg, "whitelist"))
                    cfg->default_verdict = DAQ_VERDICT_WHITELIST;
                else
                {
                    fprintf(stderr, "Invalid default verdict specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'x':
                cfg->dump_hex = true;
                break;

            case 'X':
                cfg->dump_hex = true;
                cfg->dump_ascii = true;
                break;

            case 'z':
                errno = 0;
                cfg->thread_count = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0 || cfg->thread_count == 0)
                {
                    fprintf(stderr, "Invalid thread count specified: %s\n\n", optarg);
                    return -1;
                }
                cfg->explicit_thread_count = true;
                break;

            default:
                fprintf(stderr, "Invalid argument specified (-%c)!\n", optopt);
                return -1;
        }
    }

    return 0;
}

static void print_config(DAQTestConfig *cfg)
{
    DAQTestModuleConfig *dtmc;
    unsigned i;

    printf("[Config]\n");
    printf("  Input: %s\n", cfg->input);
    printf("  Snaplen: %d\n", cfg->snaplen);
    printf("  Timeout: %ums (Allowance: ", cfg->timeout);
    if (cfg->timeout_limit)
        printf("%lu)\n", cfg->timeout_limit);
    else
        printf("Unlimited)\n");
    printf("  Module Stack:\n");
    for (dtmc = cfg->module_configs, i = 0; dtmc; dtmc = dtmc->next, i++)
    {
        printf("    %u: [%s]\n", i, dtmc->module_name);
        printf("      Mode: %s\n", daq_mode_string(dtmc->mode));
        if (dtmc->variables)
        {
            printf("      Variables:\n");
            for (i = 0; i < dtmc->num_variables; i++)
                printf("        %s\n", dtmc->variables[i]);
        }
    }
    printf("  Packet Count: ");
    if (cfg->packet_limit)
        printf("%lu\n", cfg->packet_limit);
    else
        printf("Unlimited\n");
    printf("  Batch Size: %u\n", cfg->batch_size);
    printf("  Default Verdict: %s\n", daq_verdict_string(cfg->default_verdict));
    printf("  Ping Action: %s\n", ping_action_strings[cfg->ping_action]);
    if (cfg->group_id != -1)
        printf("  GID: %d\n", cfg->group_id);
    if (cfg->user_id != -1)
        printf("  UID: %d\n", cfg->user_id);
    if (cfg->ip_addrs)
    {
        printf("  Handling ARPs for:\n");
        for (IPv4Addr *ip = cfg->ip_addrs; ip; ip = ip->next)
        {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->addr, addr_str, sizeof(addr_str));
            printf("  %s\n", addr_str);
        }
    }
    if (cfg->ignore_checksum_errors)
        printf("  Ignoring checksum errors during decode.\n");
    if (cfg->delay > 0)
        printf("  Delaying packets by %lu milliseconds.\n", cfg->delay);
    if (cfg->modify_opaque_value)
        printf("  Modifying the opaque value of flows to be the current packet count.\n");
    if (cfg->performance_mode)
        printf("  In performance mode, no decoding will be done!\n");
}

static void *processing_thread(void *arg)
{
    DAQTestThreadContext *ctxt = (DAQTestThreadContext *) arg;
    const DAQTestConfig *cfg = ctxt->cfg;
    DAQ_Stats_t stats;
    uint64_t recv_counters[MAX_DAQ_RSTAT];
    unsigned i, max_recv, recv_cnt, timeout_count;
    int rval;

    if (cfg->filter && (rval = daq_instance_set_filter(ctxt->instance, cfg->filter)) != 0)
    {
        fprintf(stderr, "Could not set BPF filter for DAQ module! (%d: %s)\n", rval, cfg->filter);
        goto exit;
    }

    if ((rval = daq_instance_start(ctxt->instance)) != DAQ_SUCCESS)
    {
        fprintf(stderr, "Could not start DAQ module: (%d: %s)\n", rval, daq_instance_get_error(ctxt->instance));
        goto exit;
    }

    printf("Snaplen: %d\n", daq_instance_get_snaplen(ctxt->instance));

    DAQ_MsgPoolInfo_t mpool_info;
    if (daq_instance_get_msg_pool_info(ctxt->instance, &mpool_info) == DAQ_SUCCESS)
    {
        printf("Message Pool Info:\n");
        printf("  Size: %u\n", mpool_info.size);
        printf("  Available: %u\n", mpool_info.available);
        printf("  Memory Usage: %zu\n", mpool_info.mem_size);
    }

    dlt = daq_instance_get_datalink_type(ctxt->instance);

    memset(recv_counters, 0, sizeof(recv_counters));
    max_recv = recv_cnt = timeout_count = 0;
    while (!ctxt->done && (!cfg->packet_limit || ctxt->packet_count < cfg->packet_limit))
    {
        /* Check to see if a config swap is pending. */
        if (ctxt->newconfig && !ctxt->oldconfig)
        {
            void *oldconfig;
            rval = daq_instance_config_swap(ctxt->instance, ctxt->newconfig, &oldconfig);
            if (rval != DAQ_SUCCESS)
                fprintf(stderr, "Failed to swap in new config: %s (%d)", daq_instance_get_error(ctxt->instance), rval);
            ctxt->newconfig = NULL;
            ctxt->oldconfig = oldconfig;
        }


        unsigned batch_size = cfg->batch_size;
        if (cfg->packet_limit)
        {
            unsigned long remainder = cfg->packet_limit - ctxt->packet_count;
            if (cfg->batch_size > remainder)
                batch_size = remainder;
        }

        DAQ_RecvStatus rstat;
        unsigned num_recv = daq_instance_msg_receive(ctxt->instance, batch_size, ctxt->msgs, &rstat);
        recv_counters[rstat]++;
        if (num_recv > max_recv)
            max_recv = num_recv;

        if (num_recv > 0)
            recv_cnt++;

        for (unsigned idx = 0; idx < num_recv; idx++)
        {
            DAQ_Msg_h msg = ctxt->msgs[idx];
            DAQ_Verdict verdict = DAQ_VERDICT_PASS;
            switch (msg->type)
            {
                case DAQ_MSG_TYPE_PACKET:
                    verdict = handle_packet_message(ctxt, msg);
                    break;
                case DAQ_MSG_TYPE_SOF:
                case DAQ_MSG_TYPE_EOF:
                    handle_flow_stats_message(ctxt, msg);
                    break;
                default:
                    break;
            }
            daq_instance_msg_finalize(ctxt->instance, msg, verdict);
        }

        if (rstat != DAQ_RSTAT_OK && rstat != DAQ_RSTAT_WOULD_BLOCK)
        {
            if (rstat == DAQ_RSTAT_TIMEOUT)
            {
                timeout_count++;
                if (!cfg->timeout_limit || timeout_count < cfg->timeout_limit)
                    continue;
            }
            else if (rstat == DAQ_RSTAT_EOF)
                printf("Read the entire file!\n");
            else if (rstat == DAQ_RSTAT_NOBUF)
                printf("Ran out of buffers to use, this really shouldn't happen...\n");
            else if (rstat == DAQ_RSTAT_ERROR)
                fprintf(stderr, "Error receiving messages: %s\n", daq_instance_get_error(ctxt->instance));
            break;
        }
    }

    printf("\nDAQ receive timed out %u times.\n", timeout_count);
    printf("Maximum messages received in a burst: %u\n", max_recv);

    printf("\n*Receive Status Counters*\n");
    const char *recv_status_string[MAX_DAQ_RSTAT] = {
        "Ok",           // DAQ_RSTAT_OK
        "Would Block",  // DAQ_RSTAT_WOULD_BLOCK
        "Timeout",      // DAQ_RSTAT_TIMEOUT
        "End of File",  // DAQ_RSTAT_EOF
        "Interrupted",  // DAQ_RSTAT_INTERRUPTED
        "No Buffers",   // DAQ_RSTAT_NOBUF
        "Error",        // DAQ_RSTAT_ERROR
        "Invalid",      // DAQ_RSTAT_INVALID
    };
    for (i = 0; i < MAX_DAQ_RSTAT; i++)
    {
        if (recv_counters[i])
            printf("  %s: %" PRIu64 "\n", recv_status_string[i], recv_counters[i]);
    }
    printf("\n");

    if ((rval = daq_instance_get_stats(ctxt->instance, &stats)) != 0)
        fprintf(stderr, "Could not get DAQ module stats: (%d: %s)\n", rval, daq_instance_get_error(ctxt->instance));
    else
    {
        if (recv_cnt > 0)
            printf("Average number of packets received per receive call: %.2f\n\n", (double)stats.packets_received / (double)recv_cnt);

        print_daq_stats(&stats);
    }

    daq_instance_stop(ctxt->instance);

exit:
    ctxt->exited = true;

    return NULL;
}

static int create_daq_config(DAQTestConfig *cfg, DAQ_Config_h *daqcfg_ptr)
{
    int rval;

    if ((rval = daq_config_new(daqcfg_ptr)) != DAQ_SUCCESS)
    {
        fprintf(stderr, "Error allocating a new DAQ configuration object! (%d)\n", rval);
        return rval;
    }

    DAQTestModuleConfig *dtmc;
    DAQ_Config_h daqcfg = *daqcfg_ptr;

    daq_config_set_input(daqcfg, cfg->input);
    daq_config_set_snaplen(daqcfg, cfg->snaplen);
    daq_config_set_timeout(daqcfg, cfg->timeout);
    if (cfg->explicit_thread_count)
        daq_config_set_total_instances(daqcfg, cfg->thread_count);

    for (dtmc = cfg->module_configs; dtmc; dtmc = dtmc->next)
    {
        DAQ_Module_h module = daq_find_module(dtmc->module_name);
        if (!module)
        {
            fprintf(stderr, "Could not find requested module: %s!\n", dtmc->module_name);
            return -1;
        }

        DAQ_ModuleConfig_h modcfg;
        if ((rval = daq_module_config_new(&modcfg, module)) != DAQ_SUCCESS)
        {
            fprintf(stderr, "Error allocating a new DAQ module configuration object! (%d)\n", rval);
            return rval;
        }

        daq_module_config_set_mode(modcfg, dtmc->mode);

        for (unsigned i = 0; i < dtmc->num_variables; i++)
        {
            char *key = dtmc->variables[i];
            char *value = strchr(key, '=');
            if (value)
            {
                *value = '\0';
                value++;
                if (*value == '\0')
                    value = NULL;
            }
            if ((rval = daq_module_config_set_variable(modcfg, key, value)) != DAQ_SUCCESS)
            {
                fprintf(stderr, "Error setting DAQ configuration variable with key '%s' and value '%s'! (%d)", key, value, rval);
                return rval;
            }
        }
        if ((rval = daq_config_push_module_config(daqcfg, modcfg)) != DAQ_SUCCESS)
        {
            fprintf(stderr, "Error pushing DAQ module configuration for '%s' onto the DAQ config! (%d)\n", dtmc->module_name, rval);
            return rval;
        }
    }
    return 0;
}

static void clear_daqtest_config(DAQTestConfig *cfg)
{
    free(cfg->module_paths);
    while (cfg->module_configs)
    {
        DAQTestModuleConfig *dtmc = cfg->module_configs;
        cfg->module_configs = dtmc->next;
        free(dtmc->variables);
        free(dtmc);
    }
    while (cfg->ip_addrs)
    {
        IPv4Addr *ip = cfg->ip_addrs;
        cfg->ip_addrs = ip->next;
        free(ip);
    }
    memset(cfg, 0, sizeof(*cfg));
}

int main(int argc, char *argv[])
{
    DAQTestConfig cfg;
    DAQ_Config_h daqcfg;
    int rval;

    if ((rval = parse_command_line(argc, argv, &cfg)) != 0)
        return rval;

    if ((!cfg.input || !cfg.module_configs->module_name) && !cfg.list_and_exit)
    {
        usage();
        return -1;
    }

    daq_set_verbosity(cfg.verbosity);
#ifdef USE_STATIC_MODULES
    daq_load_static_modules(static_modules);
#endif
    daq_load_dynamic_modules(cfg.module_paths);

    if (cfg.list_and_exit)
    {
        print_daq_modules();
        return 0;
    }

    print_config(&cfg);

    initialize_static_data();
    printf("Local MAC Address: ");
    print_mac(local_mac_addr);
    printf("\n");

    if ((rval = create_daq_config(&cfg, &daqcfg)) != DAQ_SUCCESS)
        return rval;

    /* Allocate the packet thread contexts and instantiate a DAQ instance for each. */
    DAQTestThreadContext *threads = calloc(cfg.thread_count, sizeof(*threads));

    for (unsigned i = 0; i < cfg.thread_count; i++)
    {
        DAQTestThreadContext *dttc = &threads[i];
        char errbuf[256];

        if (cfg.explicit_thread_count)
            daq_config_set_instance_id(daqcfg, i + 1);

        if ((rval = daq_instance_instantiate(daqcfg, &dttc->instance, errbuf, sizeof(errbuf))) != 0)
        {
            fprintf(stderr, "Could not construct a DAQ instance: (%d: %s)\n", rval, errbuf);
            return -1;
        }

        dttc->msgs = calloc(cfg.batch_size, sizeof(*dttc->msgs));
        dttc->cfg = &cfg;
    }

    /* Free the configuration object's memory. */
    daq_config_destroy(daqcfg);

    /* Set up the main thread to handle signals. */
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    /* Drop privileges. */
    if (cfg.group_id != -1 && setgid(cfg.group_id) == -1)
        fprintf(stderr, "Could not set GID to %d: %s (%d)\n", cfg.group_id, strerror(errno), errno);

    if (cfg.user_id != -1 && setuid(cfg.user_id) == -1)
        fprintf(stderr, "Could not set UID to %d: %s (%d)\n", cfg.user_id, strerror(errno), errno);

    /* Spin off all of the packet threads (blocking the signals we're catching). */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    for (unsigned i = 0; i < cfg.thread_count; i++)
    {
        DAQTestThreadContext *dttc = &threads[i];
        if ((rval = pthread_create(&dttc->tid, NULL, processing_thread, dttc)) != 0)
        {
            fprintf(stderr, "Error creating thread: %s (%d)\n", strerror(errno), errno);
            return -1;
        }
    }
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    /* Start the main loop. */
    const struct timespec main_sleep = { 0, 1000000 }; // 0.001 sec
    bool notdone;
    do
    {
        if (pending_signal)
        {
            switch (pending_signal)
            {
                case SIGTERM:
                case SIGINT:
                    printf("Sending interrupt to all instances.\n");
                    for (unsigned i = 0; i < cfg.thread_count; i++)
                    {
                        DAQTestThreadContext *dttc = &threads[i];
                        dttc->done = true;
                        daq_instance_interrupt(dttc->instance);
                    }
                    break;

                case SIGHUP:
                    printf("Loading config and signaling a swap for all instances.\n");
                    for (unsigned i = 0; i < cfg.thread_count; i++)
                    {
                        DAQTestThreadContext *dttc = &threads[i];
                        if (dttc->newconfig || dttc->oldconfig)
                        {
                            printf("Skipping config reload for instance %u as it is still reloading.\n", i);
                            continue;
                        }
                        void *newconfig;
                        if ((rval = daq_instance_config_load(dttc->instance, &newconfig)) == DAQ_SUCCESS)
                            dttc->newconfig = newconfig;
                        else if (rval != DAQ_ERROR_NOTSUP)
                            fprintf(stderr, "Failed to load new config for instance %u: %d", i, rval);
                    }
                    break;

                default:
                    printf("Received unrecognized signal: %d\n", pending_signal);
            }
            pending_signal = 0;
        }

        nanosleep(&main_sleep, NULL);

        /* Check if any threads are still running and perform other housekeeping... */
        notdone = false;
        for (unsigned i = 0; i < cfg.thread_count; i++)
        {
            DAQTestThreadContext *dttc = &threads[i];
            if (dttc->oldconfig)
            {
                rval = daq_instance_config_free(dttc->instance, dttc->oldconfig);
                if (rval != DAQ_SUCCESS)
                    fprintf(stderr, "Failed to free old config for instance %u: %d", i, rval);
                dttc->oldconfig = NULL;
            }
            if (!dttc->exited)
                notdone = true;
        }
    } while (notdone);

    /* Clean up all of the packet threads and tear down their DAQ instances. */
    for (unsigned i = 0; i < cfg.thread_count; i++)
    {
        DAQTestThreadContext *dttc = &threads[i];
        if ((rval = pthread_join(dttc->tid, NULL)) != 0)
        {
            fprintf(stderr, "Error joining thread: %s (%d)\n", strerror(errno), errno);
            return -1;
        }
        daq_instance_destroy(dttc->instance);
        free(dttc->msgs);
    }

    /* Clean up remaining memory to make Valgrind-like tools happy. */
    free(threads);
    clear_daqtest_config(&cfg);
    daq_unload_modules();

    return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>

#include <daq.h>
#include <sfbpf.h>

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

typedef struct _DAQTestPacket
{
    const DAQ_PktHdr_t *hdr;
    const uint8_t *packet;
    const struct ether_header *eth;
    const struct arphdr *arp;
    const struct iphdr *ip;
    const struct ip6_hdr *ip6;
    const struct icmphdr *icmp;
    const struct icmp6_hdr *icmp6;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    uint16_t vlan_tags;
} DAQTestPacket;

typedef struct _IPv4Addr
{
    struct _IPv4Addr *next;
    struct in_addr addr;
} IPv4Addr;

#define VTH_PRIORITY(vh)  ((ntohs((vh)->vth_pri_cfi_vlan) & 0xe000) >> 13)
#define VTH_CFI(vh)       ((ntohs((vh)->vth_pri_cfi_vlan) & 0x0100) >> 12)
#define VTH_VLAN(vh)      ((unsigned short)(ntohs((vh)->vth_pri_cfi_vlan) & 0x0FFF))

typedef struct _VlanTagHdr
{
    uint16_t vth_pri_cfi_vlan;
    uint16_t vth_proto;  /* protocol field... */
} VlanTagHdr;

static unsigned long packets = 0;
static unsigned long metas = 0;
static DAQ_Module_h dm = NULL;
static void *handle = NULL;
static DAQ_Mode mode = DAQ_MODE_PASSIVE;
static PingAction ping_action = PING_ACTION_PASS;
static unsigned long delay = 0;
static int performance_mode = 0;
static int modify_opaque_value = 0;
static DAQ_Verdict default_verdict = DAQ_VERDICT_PASS;
static IPv4Addr *my_ip_addrs = NULL;
static int dump_packets = 0;
static volatile sig_atomic_t notdone = 1;
static int dlt;
static bool dump_unknown_ingress = false;

const char *ping_action_strings[MAX_PING_ACTION+1] =
{
    "Pass", "Block", "Spoof", "Replace", "Blacklist", "Whitelist", "Clone"
};

static void handler(int sig)
{
    void *newconfig, *oldconfig;
    switch(sig)
    {
        case SIGTERM:
        case SIGINT:
            daq_breakloop(dm, handle);
            notdone = 0;
            break;
        case SIGHUP:
            daq_hup_prep(dm, handle, &newconfig);
            daq_hup_apply(dm, handle, newconfig, &oldconfig);
            daq_hup_post(dm, handle, oldconfig);
            break;
    }
}

static void usage()
{
    printf("Usage: daqtest -d <daq_module> -i <input>\n");
    printf("  -a <num>   Specify the number of packet aquisition loop calls (default = 0, 0 is unlimited)\n");
    printf("  -c <num>   Acquire <num> packets (default = 0, <= 0 is unlimited)\n");
    printf("  -C <key[=value]>  Set a DAQ configuration key/value pair\n");
    printf("  -D <num>   Delay all packets received by <num> milliseconds\n");
    printf("  -f <bpf>   Set the BPF based on <bpf>\n");
    printf("  -h         Display this usage text and exit\n");
    printf("  -l         Print a list of modules found and exit\n");
    printf("  -m <path>  Specify the path to the directory to search for modules\n");
    printf("  -M <mode>  Specify the mode (passive (default), inline, read-file)\n");
    printf("  -p         Performance testing mode - auto-PASS and no decoding\n");
    printf("  -P <act>   Specify the action to perform when a ping is received (none (default), block, spoof, replace, blacklist, whitelist, clone)\n");
    printf("  -s <len>   Specify the capture length in bytes (default = 1518)\n");
    printf("  -t <num>   Specify the read timeout in milliseconds (default = 0)\n");
    printf("  -v <level> Set the verbosity level of the DAQ library (default = 1)\n");
    printf("  -x         Print a hexdump of each packet received to stdout\n");
}

/*
 * Checksum routine for Internet Protocol family headers (C version) (from ping.c)
 */
static uint16_t in_cksum(uint16_t *addr, int len)
{
    int nleft = len;
    uint16_t *w = addr;
    uint32_t sum = 0;
    uint16_t answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        answer = 0;
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */

    //printf("Checksummed with length of %d, answer was %hu\n", len, answer);
    return (answer);
}

uint8_t normal_ping_data[IP_MAXPACKET];
uint8_t fake_ping_data[IP_MAXPACKET];

static void initialize_static_data()
{
    char c;
    int i;

    for (c = 0, i = 0; i < IP_MAXPACKET; c++, i++)
    {
        normal_ping_data[i] = c;
        fake_ping_data[i] = 'A';
    }
}

static int replace_icmp_data(DAQTestPacket *dtp)
{
    struct icmphdr *icmp;
    uint8_t *data;
    size_t dlen;
    int offset;
    int modified = 0;

    icmp = (struct icmphdr *) dtp->icmp;
    icmp->checksum = 0;

    dlen = ntohs(dtp->ip->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    data = (uint8_t *) icmp + sizeof(struct icmphdr);
    offset = 0;
    if (dlen > sizeof(sizeof(struct timeval)))
    {
        printf("Accounting for ping timing data (%zu bytes).\n", sizeof(struct timeval));
        offset = sizeof(struct timeval);
        data += offset;
        dlen -= offset;
    }
/*
    printf("%d bytes of data:\n", dlen);
    for (int i = 0; i < dlen; i++)
    {
        if ((i % 8) == 0)
            printf("\n");
        printf("%.2x ", data[i]);
    }
    printf("\n");
*/
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
        icmp->checksum = in_cksum((uint16_t *) icmp, ntohs(dtp->ip->tot_len) - sizeof(struct iphdr));
    }

    return modified;
}

static const uint8_t my_mac[ETH_ALEN] = { 0x00, 0x0c, 0xbd, 0x01, 0x03, 0x62 };

static uint8_t *forge_etharp_reply(DAQTestPacket *dtp, const uint8_t *mac_addr)
{
    const uint8_t *request = dtp->packet;
    uint8_t *reply;
    const struct ether_header *eth_request;
    struct ether_header *eth_reply;
    const struct ether_arp *etharp_request;
    struct ether_arp *etharp_reply;
    size_t arphdr_offset;

    arphdr_offset = sizeof(*dtp->eth) + dtp->vlan_tags * sizeof(VlanTagHdr);
    reply = calloc(arphdr_offset + sizeof(struct ether_arp), sizeof(uint8_t));

    /* Set up the ethernet header... */
    eth_request = dtp->eth;
    eth_reply = (struct ether_header *) reply;
    memcpy(eth_reply->ether_dhost, eth_request->ether_shost, ETH_ALEN);
    memcpy(eth_reply->ether_shost, eth_request->ether_dhost, ETH_ALEN);
    memcpy(reply + ETH_ALEN * 2, request + ETH_ALEN * 2, arphdr_offset - ETH_ALEN * 2);

    /* Now the ARP header... */
    etharp_request = (struct ether_arp *) dtp->arp;
    etharp_reply = (struct ether_arp *) (reply + arphdr_offset);
    memcpy(&etharp_reply->ea_hdr, &etharp_request->ea_hdr, sizeof(struct arphdr));
    etharp_reply->ea_hdr.ar_op = htons(ARPOP_REPLY);

    /* Finally, the ethernet ARP reply... */
    memcpy(etharp_reply->arp_sha, mac_addr, ETH_ALEN);
    memcpy(etharp_reply->arp_spa, etharp_request->arp_tpa, 4);
    memcpy(etharp_reply->arp_tha, etharp_request->arp_sha, ETH_ALEN);
    memcpy(etharp_reply->arp_tpa, etharp_request->arp_spa, 4);

    return reply;
}

static uint8_t *forge_icmp_reply(DAQTestPacket *dtp)
{
    const uint8_t *request = dtp->packet;
    uint8_t *reply;
    const struct ether_header *eth_request;
    struct ether_header *eth_reply;
    const struct iphdr *ip_request;
    struct iphdr *ip_reply;
    const struct icmphdr *icmp_request;
    struct icmphdr *icmp_reply;
    uint32_t dlen;
    size_t arphdr_offset;

    arphdr_offset = sizeof(*dtp->eth) + dtp->vlan_tags * sizeof(VlanTagHdr);
    reply = calloc(arphdr_offset + dtp->ip->tot_len, sizeof(uint8_t));

    /* Set up the ethernet header... */
    eth_request = dtp->eth;
    eth_reply = (struct ether_header *) reply;
    memcpy(eth_reply->ether_dhost, eth_request->ether_shost, ETH_ALEN);
    memcpy(eth_reply->ether_shost, eth_request->ether_dhost, ETH_ALEN);
    memcpy(reply + ETH_ALEN * 2, request + ETH_ALEN * 2, arphdr_offset - ETH_ALEN * 2);

    /* Now the IP header... */
    ip_request = dtp->ip;
    ip_reply = (struct iphdr *) (reply + arphdr_offset);
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
    ip_reply->check = in_cksum((uint16_t *) ip_reply, ip_reply->ihl * 4);

    /* And the ICMP header... */
    icmp_request = dtp->icmp;
    icmp_reply = (struct icmphdr *) (reply + arphdr_offset + sizeof(struct iphdr));
    icmp_reply->type = ICMP_ECHOREPLY;
    icmp_reply->code = 0;
    icmp_reply->checksum = 0;
    icmp_reply->un.echo.id = icmp_request->un.echo.id;
    icmp_reply->un.echo.sequence = icmp_request->un.echo.sequence;

    /* Copy the ICMP padding... */
    dlen = ntohs(ip_request->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    memcpy(icmp_reply + 1, icmp_request + 1, dlen);

    /* Last, but not least, checksum the ICMP packet */
    icmp_reply->checksum = in_cksum((uint16_t *) icmp_reply, ntohs(ip_request->tot_len) - sizeof(struct iphdr));

    return reply;
}

static void print_mac(const uint8_t *addr)
{
    printf("%.2hx:%.2hx:%.2hx:%.2hx:%.2hx:%.2hx", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static DAQ_Verdict process_ping(DAQTestPacket *dtp)
{
    int rc;

    switch (ping_action)
    {
        case PING_ACTION_PASS:
            break;

        case PING_ACTION_SPOOF:
            if (dtp->icmp->type == ICMP_ECHO && dtp->eth)
            {
                uint8_t *reply;
                size_t reply_len;

                reply = forge_icmp_reply(dtp);
                reply_len = sizeof(*dtp->eth) + dtp->vlan_tags * sizeof(VlanTagHdr) + ntohs(dtp->ip->tot_len);
                printf("Injecting forged ICMP reply back to source! (%zu bytes)\n", reply_len);
                rc = daq_inject(dm, handle, dtp->hdr, reply, reply_len, 1);
                if (rc == DAQ_ERROR_NOTSUP)
                    printf("This module does not support packet injection.\n");
                else if (rc != DAQ_SUCCESS)
                    printf("Failed to inject ICMP reply: %s\n", daq_get_error(dm, handle));
                free(reply);
                return DAQ_VERDICT_BLOCK;
            }

        case PING_ACTION_DROP:
            printf("Blocking the ping packet.\n");
            return DAQ_VERDICT_BLOCK;

        case PING_ACTION_REPLACE:
            if (dtp->eth)
            {
                replace_icmp_data(dtp);
                return DAQ_VERDICT_REPLACE;
            }

        case PING_ACTION_BLACKLIST:
            printf("Blacklisting the ping's flow.\n");
            return DAQ_VERDICT_BLACKLIST;

        case PING_ACTION_WHITELIST:
            printf("Whitelisting the ping's flow.\n");
            return DAQ_VERDICT_WHITELIST;

        case PING_ACTION_CLONE:
            if (dtp->eth)
            {
                printf("Injecting cloned ICMP packet.\n");
                rc = daq_inject(dm, handle, dtp->hdr, dtp->packet, dtp->hdr->caplen, 0);
                if (rc == DAQ_ERROR_NOTSUP)
                    printf("This module does not support packet injection.\n");
                else if (rc != DAQ_SUCCESS)
                    printf("Failed to inject cloned ICMP packet: %s\n", daq_get_error(dm, handle));
                printf("Blocking the original ICMP packet.\n");
                return DAQ_VERDICT_BLOCK;
            }
    }
    return DAQ_VERDICT_PASS;
}

static DAQ_Verdict process_icmp(DAQTestPacket *dtp)
{
    unsigned int dlen;

    dlen = ntohs(dtp->ip->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    printf("  ICMP: Type %hu  Code %hu  Checksum %hu  (%u bytes of data)\n",
           dtp->icmp->type, dtp->icmp->code, dtp->icmp->checksum, dlen);
    if (dtp->icmp->type == ICMP_ECHO || dtp->icmp->type == ICMP_ECHOREPLY)
    {
        printf("   Echo: ID %hu  Sequence %hu\n",
               ntohs(dtp->icmp->un.echo.id), ntohs(dtp->icmp->un.echo.sequence));
        return process_ping(dtp);
    }

    return default_verdict;
}

static DAQ_Verdict process_arp(DAQTestPacket *dtp)
{
    const struct ether_arp *etharp;
    struct in_addr addr;
    IPv4Addr *ip;
    uint8_t *reply;
    size_t reply_len;

    printf(" ARP: Hardware Type %hu (%hu)  Protocol Type %.4hX (%hu)  Operation %hu\n",
            ntohs(dtp->arp->ar_hrd), dtp->arp->ar_hln, ntohs(dtp->arp->ar_pro),
            dtp->arp->ar_pln, ntohs(dtp->arp->ar_op));

    if (ntohs(dtp->arp->ar_hrd) != ARPHRD_ETHER)
        return default_verdict;

    etharp = (struct ether_arp *) dtp->arp;

    printf("  Sender: ");
    print_mac(etharp->arp_sha);
    memcpy(&addr.s_addr, etharp->arp_spa, 4);
    printf(" (%s)\n", inet_ntoa(addr));

    printf("  Target: ");
    print_mac(etharp->arp_tha);
    memcpy(&addr.s_addr, etharp->arp_tpa, 4);
    printf(" (%s)\n", inet_ntoa(addr));

    if (ntohs(dtp->arp->ar_op) != ARPOP_REQUEST || ntohs(dtp->arp->ar_pro) != ETH_P_IP)
        return default_verdict;

    for (ip = my_ip_addrs; ip; ip = ip->next)
    {
        if (!memcmp(&addr, &ip->addr, sizeof(addr)))
            break;
    }

    /* Only perform Ethernet ARP spoofing when in ping spoofing mode and passive mode. */
    if (!ip && (ping_action != PING_ACTION_SPOOF || mode != DAQ_MODE_PASSIVE))
       return default_verdict;

    reply = forge_etharp_reply(dtp, my_mac);
    reply_len = sizeof(*dtp->eth) + dtp->vlan_tags * sizeof(VlanTagHdr) + sizeof(struct ether_arp);
    printf("Injecting forged Ethernet ARP reply back to source (%zu bytes)!\n", reply_len);
    if (daq_inject(dm, handle, dtp->hdr, reply, reply_len, 1))
        printf("Failed to inject ICMP reply: %s\n", daq_get_error(dm, handle));
    free(reply);

    return DAQ_VERDICT_BLOCK;
}

static DAQ_Verdict process_ip6(DAQTestPacket *dtp)
{
    char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN];

    /* Print source and destination IP addresses. */
    inet_ntop(AF_INET6, &dtp->ip6->ip6_src, src_addr_str, sizeof(src_addr_str));
    inet_ntop(AF_INET6, &dtp->ip6->ip6_dst, dst_addr_str, sizeof(dst_addr_str));
    printf(" IP: %s -> %s\n", src_addr_str, dst_addr_str);

    return default_verdict;
}

static DAQ_Verdict process_ip(DAQTestPacket *dtp)
{
    struct in_addr addr;
    char src_addr_str[INET_ADDRSTRLEN], dst_addr_str[INET_ADDRSTRLEN];

    /* Print source and destination IP addresses. */
    addr.s_addr = dtp->ip->saddr;
    inet_ntop(AF_INET, &addr, src_addr_str, sizeof(src_addr_str));
    addr.s_addr = dtp->ip->daddr;
    inet_ntop(AF_INET, &addr, dst_addr_str, sizeof(dst_addr_str));
    printf(" IP: %s -> %s (%hu bytes) (checksum: %hu) (type: 0x%X)\n",
            src_addr_str, dst_addr_str, ntohs(dtp->ip->tot_len), dtp->ip->check, ntohs(dtp->ip->protocol));

    switch (dtp->ip->protocol)
    {
        case IPPROTO_TCP:
            printf(" Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf(" Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf(" Protocol: ICMP\n");
            return process_icmp(dtp);
        case IPPROTO_IP:
            printf(" Protocol: IP\n");
            break;
        default:
            printf(" Protocol: unknown\n");
    }

    return default_verdict;
}

static DAQ_Verdict process_eth(DAQTestPacket *dtp)
{
    printf("MAC: ");
    print_mac(dtp->eth->ether_shost);
    printf(" -> ");
    print_mac(dtp->eth->ether_dhost);
    printf(" (%.4hX) (%u bytes)\n", ntohs(dtp->eth->ether_type), dtp->hdr->pktlen);
    if (dtp->vlan_tags > 0)
    {
        uint16_t ether_type;
        uint16_t offset;

        printf(" VLAN Tags (%hu):", dtp->vlan_tags);
        ether_type = ntohs(dtp->eth->ether_type);
        offset = sizeof(*dtp->eth);
        while (ether_type == ETH_P_8021Q)
        {
            VlanTagHdr *vlan;

            vlan = (VlanTagHdr *) (dtp->packet + offset);
            ether_type = ntohs(vlan->vth_proto);
            offset += sizeof(*vlan);
            printf(" %hu/%hu", VTH_VLAN(vlan), VTH_PRIORITY(vlan));
        }
        printf("\n");
    }
    if (dtp->arp)
        return process_arp(dtp);

    if (dtp->ip)
        return process_ip(dtp);

    if (dtp->ip6)
        return process_ip6(dtp);

    return default_verdict;
}

static DAQ_Verdict process_packet(DAQTestPacket *dtp)
{
    if (dtp->eth)
        return process_eth(dtp);

    return default_verdict;
}

static void decode_icmp(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->icmp = (struct icmphdr *) cursor;
}

static void decode_icmp6(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->icmp6 = (struct icmp6_hdr *) cursor;
}

static void decode_tcp(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->tcp = (struct tcphdr *) cursor;
}

static void decode_udp(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->udp = (struct udphdr *) cursor;
}

static void decode_ip6(DAQTestPacket *dtp, const uint8_t *cursor)
{
    uint16_t offset;

    dtp->ip6 = (struct ip6_hdr *) cursor;
    offset = sizeof(*dtp->ip6);

    switch (dtp->ip6->ip6_nxt)
    {
        case IPPROTO_TCP:
            decode_tcp(dtp, cursor + offset);
            break;
        case IPPROTO_UDP:
            decode_udp(dtp, cursor + offset);
            break;
        case IPPROTO_ICMPV6:
            decode_icmp6(dtp, cursor + offset);
            break;
    }
}

static void decode_ip(DAQTestPacket *dtp, const uint8_t *cursor)
{
    uint16_t offset;

    dtp->ip = (struct iphdr *) cursor;
    if ((dtp->ip->ihl * 4) < 20)
    {
        printf("   * Invalid IP header length: %d bytes\n", dtp->ip->ihl * 4);
        return;
    }

    offset = sizeof(*dtp->ip);

    switch (dtp->ip->protocol)
    {
        case IPPROTO_TCP:
            decode_tcp(dtp, cursor + offset);
            break;
        case IPPROTO_UDP:
            decode_udp(dtp, cursor + offset);
            break;
        case IPPROTO_ICMP:
            decode_icmp(dtp, cursor + offset);
            break;
    }
}

static void decode_arp(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->arp = (struct arphdr *) cursor;
}

static void decode_eth(DAQTestPacket *dtp, const uint8_t *cursor)
{
    uint16_t ether_type;
    uint16_t offset;

    dtp->eth = (struct ether_header *) (cursor);
    ether_type = ntohs(dtp->eth->ether_type);
    offset = sizeof(*dtp->eth);
    while (ether_type == ETH_P_8021Q)
    {
        VlanTagHdr *vlan;

        vlan = (VlanTagHdr *) (cursor + offset);
        ether_type = ntohs(vlan->vth_proto);
        offset += sizeof(*vlan);
        dtp->vlan_tags++;
    }
    if (ether_type == ETH_P_ARP)
        decode_arp(dtp, cursor + offset);
    else if (ether_type == ETH_P_IP)
        decode_ip(dtp, cursor + offset);
    else if (ether_type == ETH_P_IPV6)
        decode_ip6(dtp, cursor + offset);
}

static void decode_packet(DAQTestPacket *dtp, const uint8_t *packet, const DAQ_PktHdr_t *hdr)
{
    memset(dtp, 0, sizeof(*dtp));
    dtp->hdr = hdr;
    dtp->packet = packet;
    switch (dlt)
    {
        case DLT_EN10MB:
            return decode_eth(dtp, packet);

        case DLT_RAW:
            return decode_ip(dtp, packet);

        default:
            printf("Unhandled datalink type: %d!\n", dlt);
    }
}

static void dump(const uint8_t *data, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++)
    {
        if (i%16 == 0)
            printf("\n");
        else if (i%2 == 0)
            printf(" ");
        printf("%02x", data[i]);
    }
    printf("\n\n");
}

static DAQ_Verdict handle_packet_message(const DAQ_Msg_t *msg)
{
    DAQ_PktHdr_t *hdr;
    DAQTestPacket dtp;
    const uint8_t *data;

    hdr = daq_packet_header_from_msg(dm, handle, msg);
    data = daq_packet_data_from_msg(dm, handle, msg);

    packets++;

    if (delay)
        usleep(delay * 1000);

    if (performance_mode)
        return default_verdict;

    printf("Got Packet! Ingress = %d (Group = %d), Egress = %d (Group = %d), Addr Space ID = %u",
            hdr->ingress_index, hdr->ingress_group, hdr->egress_index, hdr->egress_group, hdr->address_space_id);
    if (hdr->flags & DAQ_PKT_FLAG_OPAQUE_IS_VALID)
        printf(", Opaque = %u", hdr->opaque);
    if (hdr->flags & DAQ_PKT_FLAG_FLOWID_IS_VALID)
        printf(", Flow ID = %u", hdr->flow_id);
    printf("\n");

    if (hdr->flags)
    {
        printf("Flags (0x%X): ", hdr->flags);
        if (hdr->flags & DAQ_PKT_FLAG_HW_TCP_CS_GOOD)
            printf("HW_TCP_CS_GOOD ");
        if (hdr->flags & DAQ_PKT_FLAG_OPAQUE_IS_VALID)
            printf("OPAQUE_IS_VALID ");
        if (hdr->flags & DAQ_PKT_FLAG_NOT_FORWARDING)
            printf("NOT_FORWARDING ");
        if (hdr->flags & DAQ_PKT_FLAG_PRE_ROUTING)
            printf("PRE_ROUTING ");
        if (hdr->flags & DAQ_PKT_FLAG_SSL_DETECTED)
            printf("SSL_DETECTED ");
        if (hdr->flags & DAQ_PKT_FLAG_SSL_SHELLO)
            printf("SSL_SHELLO ");
        if (hdr->flags & DAQ_PKT_FLAG_SSL_SERVER_KEYX)
            printf("SSL_SERVER_KEYX ");
        if (hdr->flags & DAQ_PKT_FLAG_SSL_CLIENT_KEYX)
            printf("SSL_CLIENT_KEYX ");
        if (hdr->flags & DAQ_PKT_FLAG_IGNORE_VLAN)
            printf("IGNORE_VLAN ");
        if (hdr->flags & DAQ_PKT_FLAG_REAL_ADDRESSES)
            printf("REAL_ADDRESSES ");
        if (hdr->flags & DAQ_PKT_FLAG_REAL_SIP_V6)
            printf("REAL_SIP_V6 ");
        if (hdr->flags & DAQ_PKT_FLAG_REAL_DIP_V6)
            printf("REAL_DIP_V6 ");
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
        printf("\n");
    }
    if (hdr->ingress_index < 0 && dump_unknown_ingress)
    {
        printf("Dumping packet data for packet with unknown ingress:\n");
        dump(data, hdr->caplen);
    }
    else if (dump_packets)
        dump(data, hdr->caplen);

    if (modify_opaque_value)
    {
        DAQ_ModFlow_t modify;

        modify.type = DAQ_MODFLOW_TYPE_OPAQUE;
        modify.length = sizeof(uint32_t);
        modify.value = &packets;
        daq_modify_flow(dm, handle, hdr, &modify);
    }

    decode_packet(&dtp, data, hdr);

    return process_packet(&dtp);
}

static void handle_flow_stats_message(const DAQ_Msg_t *msg)
{
    Flow_Stats_p stats = (Flow_Stats_p) msg->msg;
    char addr_str[INET6_ADDRSTRLEN];
    struct in6_addr* tmpIp;

    metas++;

    if (msg->type == DAQ_MSG_TYPE_SOF)
        printf("Received SoF metapacket.\n");
    else if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("Received EoF metapacket.\n");

    printf("  Ingress:\n");
    printf("    Interface: %d\n", stats->ingressIntf);
    printf("    Zone: %d\n", stats->ingressZone);
    printf("  Egress:\n");
    printf("    Interface: %d\n", stats->egressIntf);
    printf("    Zone: %d\n", stats->egressZone);
    printf("  Protocol: %hhu\n", stats->protocol);
    printf("  VLAN: %hu\n", stats->vlan_tag);
    printf("  Opaque: %u\n", stats->opaque);
    printf("  Initiator:\n");
    tmpIp = (struct in6_addr*)stats->initiatorIp;
    if (tmpIp->s6_addr32[0] || tmpIp->s6_addr32[1] || tmpIp->s6_addr16[4] || tmpIp->s6_addr16[5] != 0xFFFF)
        inet_ntop(AF_INET6, tmpIp, addr_str, sizeof(addr_str));
    else
        inet_ntop(AF_INET, &tmpIp->s6_addr32[3], addr_str, sizeof(addr_str));
    printf("    IP: %s", addr_str);
    if (stats->protocol == IPPROTO_UDP || stats->protocol == IPPROTO_TCP || stats->protocol == IPPROTO_ICMP || stats->protocol == IPPROTO_ICMPV6)
        printf(":%d", ntohs(stats->initiatorPort));
    printf("\n");
    if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("    Sent: %" PRIu64 " bytes (%" PRIu64 " packets)\n", stats->initiatorBytes, stats->initiatorPkts);
    printf("  Responder:\n");
    tmpIp = (struct in6_addr*)stats->responderIp;
    if (tmpIp->s6_addr32[0] || tmpIp->s6_addr32[1] || tmpIp->s6_addr16[4] || tmpIp->s6_addr16[5] != 0xFFFF)
        inet_ntop(AF_INET6, tmpIp, addr_str, sizeof(addr_str));
    else
        inet_ntop(AF_INET, &tmpIp->s6_addr32[3], addr_str, sizeof(addr_str));
    printf("    IP: %s", addr_str);
    if (stats->protocol == IPPROTO_UDP || stats->protocol == IPPROTO_TCP || stats->protocol == IPPROTO_ICMP || stats->protocol == IPPROTO_ICMPV6)
        printf(":%d", ntohs(stats->responderPort));
    printf("\n");
    if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("    Sent: %" PRIu64 " bytes (%" PRIu64 " packets)\n", stats->responderBytes, stats->responderPkts);
    printf("  First Packet: %lu seconds, %lu microseconds\n", stats->sof_timestamp.tv_sec, stats->sof_timestamp.tv_usec);
    if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("  Last Packet: %lu seconds, %lu microseconds\n", stats->eof_timestamp.tv_sec, stats->eof_timestamp.tv_usec);
}

int main(int argc, char *argv[])
{
    struct sigaction action;
    IPv4Addr *ip;
    const char **module_path = NULL;
    const char *options = "A:c:C:d:D:f:hi:lm:M:OpP:s:t:T:v:V:x";
    char *input = NULL;
    char *daq = NULL;
    char *filter = NULL;
    char addr_str[INET_ADDRSTRLEN];
    int ch;
    int flags = DAQ_CFG_PROMISC;
    DAQ_Config_h config;
    DAQ_Stats_t stats;
    int rval;
    unsigned long cnt = 0;
    char errbuf[256];
    int list_and_exit = 0;
    int verbosity = 1;
    unsigned timeout = 0;
    int snaplen = 1518;
    char *cp;
    unsigned int num_timeouts = 0;
    unsigned int timeout_count = 0;
    DAQ_Verdict verdict;
    const DAQ_Msg_t *msg;

    if ((rval = daq_config_new(&config)) != DAQ_SUCCESS)
    {
        fprintf(stderr, "Error allocating a new DAQ configuration object! (%d)\n", rval);
        return rval;
    }

    daq_set_verbosity(verbosity);

    opterr = 0;
    while ((ch = getopt(argc, argv, options)) != -1)
    {
        switch(ch)
        {
            case 'A':
                ip = calloc(1, sizeof(*ip));
                if (!inet_pton(AF_INET, optarg, &ip->addr))
                {
                    fprintf(stderr, "Invalid IP address '%s'!\n", optarg);
                    return -1;
                }
                ip->next = my_ip_addrs;
                my_ip_addrs = ip;
                break;

            case 'c':
                cnt = strtoul(optarg, NULL, 10);
                break;

            case 'C':
                cp = strchr(optarg, '=');
                if (cp)
                {
                    *cp = '\0';
                    cp++;
                    if (*cp == '\0')
                        cp = NULL;
                }
                printf("Key: %s, Value: %s\n", optarg, cp);
                daq_config_set_variable(config, optarg, cp);
                break;

            case 'd':
                daq = strdup(optarg);
                break;

            case 'D':
                delay = strtoul(optarg, NULL, 10);
                break;

            case 'f':
                filter = strdup(optarg);
                break;

            case 'h':
                usage();
                return 0;

            case 'i':
                input = strdup(optarg);
                break;

            case 'l':
                list_and_exit = 1;
                break;

            case 'm':
                module_path = calloc(1, sizeof(char *));
                module_path[0] = strdup(optarg);
                break;

            case 'M':
                for (mode = DAQ_MODE_PASSIVE; mode < MAX_DAQ_MODE; mode++)
                {
                    if (!strcmp(optarg, daq_mode_string(mode)))
                        break;
                }
                if (mode == MAX_DAQ_MODE)
                {
                    fprintf(stderr, "Invalid mode: %s!\n", optarg);
                    return -1;
                }
                break;

            case 'O':
                modify_opaque_value = 1;
                break;

            case 'p':
                performance_mode = 1;
                break;

            case 'P':
                if (!strcmp(optarg, "block"))
                    ping_action = PING_ACTION_DROP;
                else if (!strcmp(optarg, "spoof"))
                    ping_action = PING_ACTION_SPOOF;
                else if (!strcmp(optarg, "replace"))
                    ping_action = PING_ACTION_REPLACE;
                else if (!strcmp(optarg, "blacklist"))
                    ping_action = PING_ACTION_BLACKLIST;
                else if (!strcmp(optarg, "whitelist"))
                    ping_action = PING_ACTION_WHITELIST;
                else if (!strcmp(optarg, "clone"))
                    ping_action = PING_ACTION_CLONE;
                else
                {
                    fprintf(stderr, "Invalid ping argument specified (%s)!\n", optarg);
                    return -1;
                }
                break;

            case 's':
                snaplen = strtoul(optarg, NULL, 10);
                break;

            case 't':
                timeout = strtoul(optarg, NULL, 10);
                break;

            case 'T':
                num_timeouts = (unsigned int) strtoul(optarg, NULL, 10);
                break;

            case 'v':
                verbosity = strtol(optarg, NULL, 10);
                break;

            case 'V':
                if (!strcmp(optarg, "pass"))
                    default_verdict = DAQ_VERDICT_PASS;
                else if (!strcmp(optarg, "block"))
                    default_verdict = DAQ_VERDICT_BLOCK;
                else if (!strcmp(optarg, "blacklist"))
                    default_verdict = DAQ_VERDICT_BLACKLIST;
                else if (!strcmp(optarg, "whitelist"))
                    default_verdict = DAQ_VERDICT_WHITELIST;
                else
                {
                    fprintf(stderr, "Invalid default verdict specified (%s)!\n", optarg);
                    return -1;
                }
                break;

            case 'x':
                dump_packets = 1;
                break;

            default:
                fprintf(stderr, "Invalid argument specified (%c)!\n", ch);
                return -1;
        }
    }
    if ((!input || !daq) && !list_and_exit)
    {
        usage();
        return -1;
    }

    daq_set_verbosity(verbosity);
    daq_load_modules(module_path);

    if (list_and_exit)
    {
        const DAQ_VariableDesc_t *var_desc_table;
        DAQ_Module_h module;
        int num_var_descs, i;

        module = daq_modules_first();
        while (module)
        {
            printf("\n[%s]\n", daq_get_name(module));
            printf(" Version: %u\n", daq_get_version(module));
            printf(" Type: 0x%x\n", daq_get_type(module));
            num_var_descs = daq_get_variable_descriptions(module, &var_desc_table);
            if (num_var_descs)
            {
                printf(" Variables:\n");
                for (i = 0; i < num_var_descs; i++)
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

        return 0;
    }

    initialize_static_data();

    dm = daq_find_module(daq);
    if (!dm)
    {
        fprintf(stderr, "Could not find requested module: %s!\n", daq);
        return -1;
    }

    printf("Input: %s\n", input);
    printf("DAQ: %s\n", daq);
    printf("Mode: %s\n", daq_mode_string(mode));
    printf("Snaplen: %hu\n", snaplen);
    printf("Timeout: %ums (Allowance: ", timeout);
    if (num_timeouts)
        printf("%u)\n", num_timeouts);
    else
        printf("Unlimited)\n");
    printf("Packet Count: ");
    if (cnt)
        printf("%lu\n", cnt);
    else
        printf("Unlimited\n");
    printf("Default Verdict: %s\n", daq_verdict_string(default_verdict));
    printf("Ping Action: %s\n", ping_action_strings[ping_action]);
    printf("Handling ARPs for:\n");
    for (ip = my_ip_addrs; ip; ip = ip->next)
    {
        inet_ntop(AF_INET, &ip->addr, addr_str, sizeof(addr_str));
        printf("  %s\n", addr_str);
    }
    if (delay > 0)
        printf("Delaying packets by %lu milliseconds.\n", delay);
    if (modify_opaque_value)
        printf("Modifying the opaque value of flows to be the current packet count.\n");
    if (performance_mode)
        printf("In performance mode, no decoding will be done!\n");

    daq_config_set_input(config, input);
    daq_config_set_snaplen(config, snaplen);
    daq_config_set_timeout(config, timeout);
    daq_config_set_mode(config, mode);
    daq_config_set_flag(config, flags);

    if ((rval = daq_initialize(dm, config, &handle, errbuf, sizeof(errbuf))) != 0)
    {
        fprintf(stderr, "Could not initialize DAQ module: (%d: %s)\n", rval, errbuf);
        return -1;
    }

    if (daq_get_capabilities(dm, handle) & DAQ_CAPA_DEVICE_INDEX)
    {
        printf("Dumping packets with unknown ingress interface.\n");
        dump_unknown_ingress = true;
    }

    /* Free the configuration object's memory. */
    daq_config_destroy(config);

    if (filter && (rval = daq_set_filter(dm, handle, filter)) != 0)
    {
        fprintf(stderr, "Could not set BPF filter for DAQ module! (%d: %s)\n", rval, filter);
        return -1;
    }

    if ((rval = daq_start(dm, handle)) != 0)
    {
        fprintf(stderr, "Could not start DAQ module: (%d: %s)\n", rval, daq_get_error(dm, handle));
        return -1;
    }

    dlt = daq_get_datalink_type(dm, handle);

    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    while (notdone && (!cnt || packets < cnt))
    {
        rval = daq_msg_receive(dm, handle, &msg);
        //printf("rval = %d, msg = %p\n", rval, msg);
        if (rval < 0)
        {
            if (rval == DAQ_READFILE_EOF && mode == DAQ_MODE_READ_FILE)
                printf("Read the entire file!\n");
            else
                fprintf(stderr, "Error acquiring packets! (%d)\n", rval);
            break;
        }
        /* Timeout? */
        if (!msg)
        {
            timeout_count++;
            if (num_timeouts && timeout_count >= num_timeouts)
                break;
            continue;
        }
        verdict = DAQ_VERDICT_PASS;
        switch (msg->type)
        {
            case DAQ_MSG_TYPE_PACKET:
                verdict = handle_packet_message(msg);
                break;
            case DAQ_MSG_TYPE_SOF:
            case DAQ_MSG_TYPE_EOF:
                handle_flow_stats_message(msg);
                break;
            default:
                break;
        }
        daq_msg_finalize(dm, handle, msg, verdict);
    }

    printf("DAQ receive timed out %u times.\n", timeout_count);

    if ((rval = daq_get_stats(dm, handle, &stats)) != 0)
        fprintf(stderr, "Could not get DAQ module stats: (%d: %s)\n", rval, daq_get_error(dm, handle));
    else
        daq_print_stats(&stats, NULL);

    daq_stop(dm, handle);

    daq_shutdown(dm, handle);

    return 0;
}


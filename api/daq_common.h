/*
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

#ifndef _DAQ_COMMON_H
#define _DAQ_COMMON_H

#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#ifndef WIN32
#include <sys/time.h>
#else
/* for struct timeavl */
#include <winsock2.h>
#include <windows.h>
#endif

#ifndef DAQ_SO_PUBLIC
#if defined _WIN32 || defined __CYGWIN__
#  if defined DAQ_DLL
#    ifdef __GNUC__
#      define DAQ_SO_PUBLIC __attribute__((dllexport))
#    else
#      define DAQ_SO_PUBLIC __declspec(dllexport)
#    endif
#  else
#    ifdef __GNUC__
#      define DAQ_SO_PUBLIC __attribute__((dllimport))
#    else
#      define DAQ_SO_PUBLIC __declspec(dllimport)
#    endif
#  endif
#  define DLL_LOCAL
#else
#  ifdef HAVE_VISIBILITY
#    define DAQ_SO_PUBLIC  __attribute__ ((visibility("default")))
#    define DAQ_SO_PRIVATE __attribute__ ((visibility("hidden")))
#  else
#    define DAQ_SO_PUBLIC
#    define DAQ_SO_PRIVATE
#  endif
#endif
#endif

#ifdef _WIN32
# ifdef DAQ_DLL
#  define DAQ_LINKAGE DAQ_SO_PUBLIC
# else
#  define DAQ_LINKAGE
# endif
#else
# define DAQ_LINKAGE DAQ_SO_PUBLIC
#endif

#define DAQ_SUCCESS          0  /* Success! */
#define DAQ_ERROR           -1  /* Generic error */
#define DAQ_ERROR_NOMEM     -2  /* Out of memory error */
#define DAQ_ERROR_NODEV     -3  /* No such device error */
#define DAQ_ERROR_NOTSUP    -4  /* Functionality is unsupported error */
#define DAQ_ERROR_NOMOD     -5  /* No module specified error */
#define DAQ_ERROR_NOCTX     -6  /* No context specified error */
#define DAQ_ERROR_INVAL     -7  /* Invalid argument/request error */
#define DAQ_ERROR_EXISTS    -8  /* Argument or device already exists */
#define DAQ_ERROR_AGAIN     -9  /* Try again */
#define DAQ_READFILE_EOF    -42 /* Hit the end of the file being read! */

typedef const struct _daq_module_api *DAQ_Module_h;
typedef const struct _daq_instance *DAQ_Instance_h;

typedef enum
{
    DAQ_MSG_TYPE_PACKET = 1,    /* Packet data */
    DAQ_MSG_TYPE_PAYLOAD,       /* Payload data */
    DAQ_MSG_TYPE_SOF,           /* Start of Flow statistics */
    DAQ_MSG_TYPE_EOF,           /* End of Flow statistics */
    DAQ_MSG_TYPE_VPN_LOGIN,     /* VPN login info */
    DAQ_MSG_TYPE_VPN_LOGOUT,    /* VPN logout info */
    DAQ_MSG_TYPE_HA_STATE,      /* HA State blob */
    MAX_DAQ_MSG_TYPE
} DAQ_MsgType;

typedef struct _daq_msg
{
    DAQ_MsgType type;
    void *msg;
} DAQ_Msg_t;

#define DAQ_PKT_FLAG_HW_TCP_CS_GOOD     0x00001 /* The DAQ module reports that the checksum for this packet is good. */
#define DAQ_PKT_FLAG_OPAQUE_IS_VALID    0x00002 /* The DAQ module actively set the opaque value in the DAQ packet header. */
#define DAQ_PKT_FLAG_NOT_FORWARDING     0x00004 /* The DAQ module will not be actively forwarding this packet
                                                    regardless of the verdict (e.g, Passive or Inline Tap interfaces). */
#define DAQ_PKT_FLAG_PRE_ROUTING        0x00008 /* The packet is being routed via us but packet modifications
                                                    (MAC and TTL) have not yet been made. */
#define DAQ_PKT_FLAG_SSL_DETECTED       0x00010 /* Packet is ssl client hello */
#define DAQ_PKT_FLAG_SSL_SHELLO         0x00020 /* Packet is ssl server hello */
#define DAQ_PKT_FLAG_SSL_SERVER_KEYX    0x00040 /* Packet is ssl server keyx */
#define DAQ_PKT_FLAG_SSL_CLIENT_KEYX    0x00080 /* Packet is ssl client keyx */
#define DAQ_PKT_FLAG_IGNORE_VLAN        0x00100 /* Application should ignore VLAN tags on the packet */
#define DAQ_PKT_FLAG_REAL_ADDRESSES     0x00200 /* The real address values in the header are valid */
#define DAQ_PKT_FLAG_REAL_SIP_V6        0x00400 /* The real source address is IPv6 */
#define DAQ_PKT_FLAG_REAL_DIP_V6        0x00800 /* The real destination address is IPv6 */
#define DAQ_PKT_FLAG_FLOWID_IS_VALID    0x01000 /* The DAQ module actively set the flow ID value in the DAQ packet header. */
#define DAQ_PKT_FLAG_LOCALLY_DESTINED   0x02000 /* The packet is destined for local delivery */
#define DAQ_PKT_FLAG_LOCALLY_ORIGINATED 0x04000 /* The packet was originated locally */
#define DAQ_PKT_FLAG_SCRUBBED_TCP_OPTS  0x08000 /* Scrubbed tcp options may be available */
#define DAQ_PKT_FLAG_HA_STATE_AVAIL     0x10000 /* HA State is availble for the flow this packet is associated with. */
#define DAQ_PKT_FLAG_ERROR_PACKET       0x20000 /* Lower level reports that the packet has errors. */
#define DAQ_PKT_FLAG_RETRY_PACKET       0x40000 /* Packet is from the retry queue. */
#define DAQ_PKT_FLAG_PARSED             0x80000 /* Packet has been parsed and has decode data is available. */

#define DAQ_PKT_OFFSET_INVALID          0x0fffffff

typedef union {
    uint32_t all;

    struct {
        uint32_t l2:1;              /* Parsed known L2 protocol */
        uint32_t l2_checksum:1;     /* L2 checksum was calculated and validated. */
        uint32_t l3:1;              /* Parsed known L3 protocol */
        uint32_t l3_checksum:1;     /* L3 checksum was calculated and validated. */
        uint32_t l4:1;              /* Parsed known L4 protocol */
        uint32_t l4_checksum:1;     /* L4 checksum was calculated and validated. */

        uint32_t vlan:1;            /* VLAN header found and parsed */
        uint32_t vlan_qinq:1;       /* Stacked VLAN header (QinQ) found and parsed */

        uint32_t ipv4:1;
        uint32_t ipv6:1;

        uint32_t udp:1;
        uint32_t tcp:1;
        uint32_t icmp:1;
    };
} DAQ_PktDecodeFlags_t;

typedef struct _daq_pkt_decode_data
{
    uint32_t l2_offset;
    uint16_t vlan_s_tag;
    uint16_t vlan_c_tag;
    uint32_t l3_offset;
    uint32_t l3_protocol;
    uint32_t l3_len;
    uint32_t l4_offset;
    uint32_t l4_protocol;
    uint32_t l4_len;
    uint32_t payload_offset;
    DAQ_PktDecodeFlags_t flags;
} DAQ_PktDecodeData_t;

/* The DAQ packet header structure passed to DAQ Analysis Functions.
 * This should NEVER be modified by user applications. */
#define DAQ_PKTHDR_UNKNOWN  -1  /* Ingress or Egress not known */
#define DAQ_PKTHDR_FLOOD    -2  /* Egress is flooding */
typedef struct _daq_pkt_hdr
{
    struct timeval ts;          /* Timestamp */
    uint32_t caplen;            /* Length of the portion present */
    uint32_t pktlen;            /* Length of this packet (off wire) */
    uint16_t address_space_id;  /* Unique ID of the address space */
    int32_t ingress_index;      /* Index of the inbound interface. */
    int32_t egress_index;       /* Index of the outbound interface. */
    int32_t ingress_group;      /* Index of the inbound group. */
    int32_t egress_group;       /* Index of the outbound group. */
    uint32_t opaque;            /* Opaque context value from the DAQ module or underlying hardware.
                                    Directly related to the opaque value in FlowStats. */
    uint32_t flow_id;           /* Flow ID value provided from the DAQ module or underlying hardware. */
    uint32_t flags;             /* Flags for the packet (DAQ_PKT_FLAG_*) */

    DAQ_PktDecodeData_t decode_data;    /* Decoded packet data */

    void *priv_ptr;             /* Private data pointer (for DAQ module use only) */

    /* Real values for NAT'ed connections */
    struct in6_addr real_sIP;
    struct in6_addr real_dIP;
    uint16_t n_real_sPort;
    uint16_t n_real_dPort;
} DAQ_PktHdr_t;

typedef struct _daq_flow_desc
{
    /* Interface/Flow ID/Address Space Information */
    int32_t ingress_index;  /* Index of the inbound interface */
    int32_t egress_index;   /* Index of the outbound interface */
    int32_t ingress_group;  /* Index of the inbound group */
    int32_t egress_group;   /* Index of the outbound group */
    uint32_t flow_id;       /* Flow ID value provided from the DAQ module or underlying hardware. */
    uint16_t addr_space_id; /* Address space this traffic belongs to */
    /* L2 Information */
    uint16_t vlan_tag;
    /* L3 Information */
    union {
        struct in_addr in_addr;
        struct in6_addr in6_addr;
    } src_addr;
    union {
        struct in_addr in_addr;
        struct in6_addr in6_addr;
    } dst_addr;
    uint8_t family;
    /* L4 Information */
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
} DAQ_FlowDesc_t;

#define DAQ_PLD_FLAG_REVERSED   0x1 /* L3/L4 addresses/ports are the reverse of the flow desc */
typedef struct _daq_payload_hdr
{
    struct timeval ts;          /* Timestamp */
    uint32_t len;               /* Length of the payload */
    uint32_t flags;             /* Flags for the payload (DAQ_PLD_FLAG_*) */
    DAQ_FlowDesc_t flow_desc;   /* Description of the flow this payload came from */
} DAQ_PayloadHdr_t;

/* HA state binary blob descriptor used for DAQ_MSG_TYPE_HA_STATE and DAQ_QUERYFLOW_TYPE_HA_STATE. */
typedef struct _daq_ha_state_data
{
    uint32_t length;
    void *data;
} DAQ_HA_State_Data_t;

/* Flow statistics structure used for DAQ_MSG_TYPE_TYPE_SOF and DAQ_MSG_TYPE_TYPE_EOF. */
typedef struct _flow_stats
{
    int32_t ingressZone;
    int32_t egressZone;
    int32_t ingressIntf;
    int32_t egressIntf;
    /* The IP addresses should be IPv6 or IPv6 representation of IPv4 (::FFFF:<ipv4>) */
    uint8_t initiatorIp[16];
    uint8_t responderIp[16];
    uint16_t initiatorPort;
    uint16_t responderPort;
    uint32_t opaque;
    uint64_t initiatorPkts;         /* Not populated for SoF stats. */
    uint64_t responderPkts;         /* Not populated for SoF stats. */
    uint64_t initiatorBytes;        /* Not populated for SoF stats. */
    uint64_t responderBytes;        /* Not populated for SoF stats. */
    struct timeval sof_timestamp;
    struct timeval eof_timestamp;   /* Not populated for SoF stats. */
    uint16_t vlan_tag;
    uint16_t address_space_id;
    uint8_t protocol;
} Flow_Stats_t;

/* VPN session type used by DAQ_VPN_Login_Info_t for DAQ_MSG_TYPE_TYPE_VPN_LOGIN. */
typedef enum {
    NP_IDFW_VPN_SESSION_TYPE_UNKNOWN = 0,
    NP_IDFW_VPN_SESSION_TYPE_RA_IKEV1 = 1,
    NP_IDFW_VPN_SESSION_TYPE_RA_IKEV2 = 2,
    NP_IDFW_VPN_SESSION_TYPE_RA_SSLVPN = 3,
    NP_IDFW_VPN_SESSION_TYPE_RA_SSLVPN_CLIENTLESS = 4,
    NP_IDFW_VPN_SESSION_TYPE_LAN2LAN_IKEV1 = 5,
    NP_IDFW_VPN_SESSION_TYPE_LAN2LAN_IKEV2 = 6,
    NP_IDFW_VPN_SESSION_TYPE_MAX,
} np_idfw_vpn_session_type_t;

/* VPN logout info used for DAQ_VPN_Login_Info_t and DAQ_MSG_TYPE_TYPE_VPN_LOGOUT. */
typedef struct _daq_vpn_info
{
    uint8_t ip[16];
    uint32_t id;
} DAQ_VPN_Info_t, *DAQ_VPN_Info_p;

/* VPN login info used for DAQ_MSG_TYPE_TYPE_VPN_LOGIN. */
#define DAQ_VPN_INFO_MAX_USER_NAME_LEN  256
typedef struct _daq_vpn_login_info
{
    DAQ_VPN_Info_t info;
    uint32_t os;
    np_idfw_vpn_session_type_t type;
    char user[DAQ_VPN_INFO_MAX_USER_NAME_LEN + 1];
} DAQ_VPN_Login_Info_t, *DAQ_VPN_Login_Info_p;

/*
 * Flow modification definitions.
 */

#define DAQ_MODFLOW_TYPE_OPAQUE     1
#define DAQ_MODFLOW_TYPE_HA_STATE   2
#define DAQ_MODFLOW_TYPE_SET_QOS_ID 3
typedef struct _daq_modflow
{
    int type;
    uint32_t length;
    const void *value;
} DAQ_ModFlow_t;


/*
 * Flow querying definitions.
 */

#define DAQ_QUERYFLOW_TYPE_TCP_SCRUBBED_SYN     1
#define DAQ_QUERYFLOW_TYPE_TCP_SCRUBBED_SYN_ACK 2
#define DAQ_QUERYFLOW_TYPE_HA_STATE             3
typedef struct _daq_queryflow
{
    int type;
    uint32_t length;
    void *value;
} DAQ_QueryFlow_t;

/* TCP option flags Used by DAQ_TCP_Opts_t. */
typedef enum
{
    DAQ_TCP_OPTS_MSS_CHANGED = 0x01,
    DAQ_TCP_OPTS_WIN_SCALE_CHANGED = 0x02,
    DAQ_TCP_OPTS_SACK_CHANGED = 0x04,
    DAQ_TCP_OPTS_TS_CHANGED = 0x08,
} DAQ_TCP_Opts_flags_t;

/* This structure contains TCP options before modification by the underlying
    hardware.  It is used for DAQ_QUERYFLOW_TYPE_TCP_SCRUBBED_SYN and
    DAQ_QUERYFLOW_TYPE_TCP_SCRUBBED_SYN_ACK. */
typedef struct daq_tcp_opts_t_
{
    uint8_t flags;
    uint8_t window_scale;
    uint16_t mss;
    uint8_t window_scale_position;
    uint8_t ts_position;
    uint8_t mss_position;
    uint8_t sack_ok_position;
    uint32_t ts_value;
} DAQ_TCP_Opts_t;


/* Packet verdicts passed to daq_msg_finalize(). */
typedef enum {
    DAQ_VERDICT_PASS,       /* Pass the packet. */
    DAQ_VERDICT_BLOCK,      /* Block the packet. */
    DAQ_VERDICT_REPLACE,    /* Pass a packet that has been modified in-place. (No resizing allowed!) */
    DAQ_VERDICT_WHITELIST,  /* Pass the packet and fastpath all future packets in the same flow systemwide. */
    DAQ_VERDICT_BLACKLIST,  /* Block the packet and block all future packets in the same flow systemwide. */
    DAQ_VERDICT_IGNORE,     /* Pass the packet and fastpath all future packets in the same flow for this application. */
    DAQ_VERDICT_RETRY,      /* Hold the packet briefly and resend it to Snort while Snort waits for external response.
                               Drop any new packets received on that flow while holding before sending them to Snort. */
    MAX_DAQ_VERDICT
} DAQ_Verdict;

typedef enum {
    DAQ_MODE_NONE,
    DAQ_MODE_PASSIVE,
    DAQ_MODE_INLINE,
    DAQ_MODE_READ_FILE,
    MAX_DAQ_MODE
} DAQ_Mode;

typedef struct _daq_module_config *DAQ_ModuleConfig_h;
typedef struct _daq_config *DAQ_Config_h;

#define DAQ_VAR_DESC_REQUIRES_ARGUMENT  0x01
#define DAQ_VAR_DESC_FORBIDS_ARGUMENT   0x02
typedef struct _daq_variable_desc
{
    const char *name;
    const char *description;
    uint32_t flags;
} DAQ_VariableDesc_t;

typedef enum {
    DAQ_STATE_UNINITIALIZED,
    DAQ_STATE_INITIALIZED,
    DAQ_STATE_STARTED,
    DAQ_STATE_STOPPED,
    DAQ_STATE_UNKNOWN,
    MAX_DAQ_STATE
} DAQ_State;

typedef struct _daq_stats
{
    uint64_t hw_packets_received;       /* Packets received by the hardware */
    uint64_t hw_packets_dropped;        /* Packets dropped by the hardware */
    uint64_t packets_received;          /* Packets received by this instance */
    uint64_t packets_filtered;          /* Packets filtered by this instance's BPF */
    uint64_t packets_injected;          /* Packets injected by this instance */
    uint64_t verdicts[MAX_DAQ_VERDICT]; /* Counters of packets handled per-verdict. */
} DAQ_Stats_t;

#define DAQ_DP_TUNNEL_TYPE_NON_TUNNEL 0
#define DAQ_DP_TUNNEL_TYPE_GTP_TUNNEL 1
#define DAQ_DP_TUNNEL_TYPE_OTHER_TUNNEL 2

typedef struct _DAQ_DP_key_t {
    uint32_t af;                /* AF_INET or AF_INET6 */
    union {
        struct in_addr src_ip4;
        struct in6_addr src_ip6;
    } sa;
    union {
        struct in_addr dst_ip4;
        struct in6_addr dst_ip6;
    } da;
    uint8_t protocol;           /* TCP or UDP (IPPROTO_TCP or IPPROTO_UDP )*/
    uint16_t src_port;          /* TCP/UDP source port */
    uint16_t dst_port;          /* TCP/UDP destination port */
    uint16_t address_space_id;  /* Address Space ID */
    uint16_t tunnel_type;       /* Tunnel type */
    uint16_t vlan_id;           /* VLAN ID */
    uint16_t vlan_cnots;
} DAQ_DP_key_t;

/* DAQ module type flags */
#define DAQ_TYPE_FILE_CAPABLE   0x01    /* can read from a file */
#define DAQ_TYPE_INTF_CAPABLE   0x02    /* can open live interfaces */
#define DAQ_TYPE_INLINE_CAPABLE 0x04    /* can form an inline bridge */
#define DAQ_TYPE_MULTI_INSTANCE 0x08    /* can be instantiated multiple times */
#define DAQ_TYPE_NO_UNPRIV      0x10    /* can not run unprivileged */
#define DAQ_TYPE_WRAPPER        0x20    /* must decorate another DAQ module */

/* DAQ module capability flags */
#define DAQ_CAPA_NONE           0x00000000   /* no capabilities */
#define DAQ_CAPA_BLOCK          0x00000001   /* can block packets */
#define DAQ_CAPA_REPLACE        0x00000002   /* can replace/modify packet data (up to the original data size) */
#define DAQ_CAPA_INJECT         0x00000004   /* can inject packets */
#define DAQ_CAPA_WHITELIST      0x00000008   /* can whitelist flows */
#define DAQ_CAPA_BLACKLIST      0x00000010   /* can blacklist flows */
#define DAQ_CAPA_UNPRIV_START   0x00000020   /* can call start() without root privileges */
#define DAQ_CAPA_BREAKLOOP      0x00000040   /* can call breakloop() to break acquisition loop */
#define DAQ_CAPA_BPF            0x00000080   /* can call set_filter() to establish a BPF */
#define DAQ_CAPA_DEVICE_INDEX   0x00000100   /* can consistently fill the device_index field in DAQ_PktHdr */
#define DAQ_CAPA_INJECT_RAW     0x00000200   /* injection of raw packets (no layer-2 headers) */
#define DAQ_CAPA_RETRY          0x00000400   /* resend packet to Snort after brief delay. */
#define DAQ_CAPA_DECODE_GTP     0x00000800   /* decodes and tracks flows within GTP. */
#define DAQ_CAPA_DECODE_TEREDO  0x00001000   /* decodes and tracks flows within Teredo. */
#define DAQ_CAPA_DECODE_GRE     0x00002000   /* decodes and tracks flows within GRE. */
#define DAQ_CAPA_DECODE_4IN4    0x00004000   /* decodes and tracks flows of IPv4 within IPv4. */
#define DAQ_CAPA_DECODE_6IN4    0x00008000   /* decodes and tracks flows of IPv6 within IPv4. */
#define DAQ_CAPA_DECODE_4IN6    0x00010000   /* decodes and tracks flows of IPv4 within IPv6. */
#define DAQ_CAPA_DECODE_6IN6    0x00020000   /* decodes and tracks flows of IPv6 within IPv6. */

#endif /* _DAQ_COMMON_H */

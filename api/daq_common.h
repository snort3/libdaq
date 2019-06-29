/*
** Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>

#ifndef DAQ_SO_PUBLIC
#  ifdef HAVE_VISIBILITY
#    define DAQ_SO_PUBLIC  __attribute__ ((visibility("default")))
#    define DAQ_SO_PRIVATE __attribute__ ((visibility("hidden")))
#  else
#    define DAQ_SO_PUBLIC
#    define DAQ_SO_PRIVATE
#  endif
#endif

#define DAQ_LINKAGE DAQ_SO_PUBLIC

typedef const struct _daq_module_api *DAQ_Module_h;
typedef struct _daq_module_config *DAQ_ModuleConfig_h;
typedef struct _daq_config *DAQ_Config_h;
typedef struct _daq_instance *DAQ_Instance_h;
typedef struct _daq_module_instance *DAQ_ModuleInstance_h;
typedef const struct _daq_msg *DAQ_Msg_h;

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

typedef enum
{
    DAQ_RSTAT_OK = 0,
    DAQ_RSTAT_WOULD_BLOCK,
    DAQ_RSTAT_TIMEOUT,
    DAQ_RSTAT_EOF,
    DAQ_RSTAT_INTERRUPTED,
    DAQ_RSTAT_NOBUF,
    DAQ_RSTAT_ERROR,
    DAQ_RSTAT_INVALID,
    MAX_DAQ_RSTAT
} DAQ_RecvStatus;

typedef enum
{
    DAQ_MSG_TYPE_PACKET = 1,    /* Packet data */
    DAQ_MSG_TYPE_PAYLOAD,       /* Payload data */
    DAQ_MSG_TYPE_SOF,           /* Start of Flow statistics */
    DAQ_MSG_TYPE_EOF,           /* End of Flow statistics */
    DAQ_MSG_TYPE_HA_STATE,      /* HA State blob */
    LAST_BUILTIN_DAQ_MSG_TYPE = 1024,   /* End of reserved space for "official" DAQ message types.
                                           Any externally defined message types should be larger than this. */
    MAX_DAQ_MSG_TYPE = UINT16_MAX
} DAQ_MsgType;

/* NOTE: The internals of this message structure are only visible for performance reasons and
    for use by DAQ modules.  Applications should use the pseudo-opaque DAQ_Msg_h and the inline
    accessor functions (daq_msg_*) from daq.h. */

typedef struct _daq_msg
{
    DAQ_MsgType type;           /* Message type (one of DAQ_MsgType or from the user-defined range). */
    size_t hdr_len;             /* Length of the header structure pointed to by 'hdr'. */
    void *hdr;                  /* Pointer to the message header structure for this message. */
    uint32_t data_len;          /* Length of the data pointed to by 'data'.  Should be 0 if 'data' is NULL. */
    uint8_t *data;              /* Pointer to the variable-length message data. (Optional) */
    DAQ_ModuleInstance_h owner; /* Handle for the module instance this message belongs to. */
    void *priv;                 /* Pointer to module instance's private data for this message. (Optional) */
} DAQ_Msg_t;

#define DAQ_PKT_FLAG_HW_TCP_CS_GOOD     0x00001 /* The DAQ module reports that the checksum for this packet is good. */
#define DAQ_PKT_FLAG_OPAQUE_IS_VALID    0x00002 /* The DAQ module actively set the opaque value in the DAQ packet header. */
#define DAQ_PKT_FLAG_NOT_FORWARDING     0x00004 /* The DAQ module will not be actively forwarding this packet
                                                    regardless of the verdict (e.g, Passive or Inline Tap interfaces). */
#define DAQ_PKT_FLAG_PRE_ROUTING        0x00008 /* The packet is being routed via us but packet modifications
                                                    (MAC and TTL) have not yet been made. */
#define DAQ_PKT_FLAG_IGNORE_VLAN        0x00010 /* Ignore vlan tags in the packet */
#define DAQ_PKT_FLAG_REAL_ADDRESSES     0x00020 /* The real address values in the header are valid */
#define DAQ_PKT_FLAG_REAL_SIP_V6        0x00040 /* The real source address is IPv6 */
#define DAQ_PKT_FLAG_REAL_DIP_V6        0x00080 /* The real destination address is IPv6 */
#define DAQ_PKT_FLAG_FLOWID_IS_VALID    0x00100 /* The DAQ module actively set the flow ID value in the DAQ packet header. */
#define DAQ_PKT_FLAG_LOCALLY_DESTINED   0x00200 /* The packet is destined for local delivery */
#define DAQ_PKT_FLAG_LOCALLY_ORIGINATED 0x00400 /* The packet was originated locally */
#define DAQ_PKT_FLAG_SCRUBBED_TCP_OPTS  0x00800 /* Scrubbed tcp options maybe available */
#define DAQ_PKT_FLAG_HA_STATE_AVAIL     0x01000 /* HA State is availble for the flow this packet is associated with. */
#define DAQ_PKT_FLAG_ERROR_PACKET       0x02000 /* Lower level reports that the packet has errors. */
#define DAQ_PKT_FLAG_RETRY_PACKET       0x04000 /* Packet is from the retry queue. */
#define DAQ_PKT_FLAG_TRACE_ENABLED      0x08000 /* Tracing due to packet trace or capture with trace */
#define DAQ_PKT_FLAG_SIMULATED          0x10000 /* Packet is simulated/virtual */
#define DAQ_PKT_FLAG_PARSED             0x20000 /* Packet has been parsed and has decode data is available. */

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
    } flags;
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
    uint32_t pktlen;            /* Original length of this packet (off wire) */
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

/* HA state binary blob descriptor used for DAQ_MSG_TYPE_HA_STATE. */
typedef struct _daq_ha_state_data
{
    uint32_t length;
    void *data;
} DAQ_HA_State_Data_t;

/* Flow statistics structure used for DAQ_MSG_TYPE_SOF and DAQ_MSG_TYPE_EOF. */
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
    /* QoS related variables */
    uint64_t initiatorPktsDropped;  /* Not populated for SoF stats. */
    uint64_t responderPktsDropped;  /* Not populated for SoF stats. */
    uint64_t initiatorBytesDropped; /* Not populated for SoF stats. */
    uint64_t responderBytesDropped; /* Not populated for SoF stats. */
    uint8_t isQoSAppliedOnSrcIntf;  /* Not populated for SoF stats. */
    struct timeval sof_timestamp;
    struct timeval eof_timestamp;   /* Not populated for SoF stats. */
    uint16_t vlan_tag;
    uint16_t address_space_id;
    uint8_t protocol;
} Flow_Stats_t;

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

typedef struct _daq_msg_pool_info
{
    uint32_t size;
    uint32_t available;
    size_t mem_size;
} DAQ_MsgPoolInfo_t;


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
#define DAQ_CAPA_INTERRUPT      0x00000040   /* can call interrupt() to abort a receive call early */
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
#define DAQ_CAPA_DECODE_MPLS    0x00040000   /* decodes and tracks flows within MPLS. */

/*
 * DAQ I/O Controls (DIOCTLs)
 */
typedef enum
{
    DIOCTL_GET_DEVICE_INDEX = 1,
    DIOCTL_SET_FLOW_OPAQUE,
    DIOCTL_SET_FLOW_HA_STATE,
    DIOCTL_GET_FLOW_HA_STATE,
    DIOCTL_SET_FLOW_QOS_ID,
    DIOCTL_SET_PACKET_TRACE_DATA,
    DIOCTL_SET_PACKET_VERDICT_REASON,
    DIOCTL_SET_FLOW_PRESERVE,
    DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN,
    DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN_ACK,
    DIOCTL_CREATE_EXPECTED_FLOW,
    LAST_BUILTIN_DIOCTL_CMD = 1024,     /* End of reserved space for "official" DAQ ioctl commands.
                                           Any externally defined ioctl commands should be larger than this. */
    MAX_DIOCTL_CMD = UINT16_MAX
} DAQ_IoctlCmd;

/*
 * Command: DIOCTL_GET_DEVICE_INDEX
 * Description: Given a device name, query the index (as used in ingress/egress_index) associated with it.
 * Argument: DIOCTL_QueryDeviceIndex
 */
typedef struct
{
    const char *device; // [in] Device name being queried
    int index;          // [out] Index of the queried device
} DIOCTL_QueryDeviceIndex;

/*
 * Command: DIOCTL_SET_FLOW_OPAQUE
 * Description: Set a 32-bit opaque value on the flow associated with the DAQ message.
 * Argument: DIOCTL_SetFlowOpaque
 */
typedef struct
{
    DAQ_Msg_h msg;      // [in] Message belonging to the flow to be modified
    uint32_t value;     // [in] The 32-bit opaque value to be set
} DIOCTL_SetFlowOpaque;

/*
 * Command: DIOCTL_SET_FLOW_HA_STATE
 * Description: Store a binary HA state blob on the flow associated with the DAQ message.
 * Argument: DIOCTL_FlowHAState
 *
 * Command: DIOCTL_GET_FLOW_HA_STATE
 * Description: Retrieve the binary HA state blob on the flow associated with the DAQ message.
 * Argument: DIOCTL_FlowHAState
 */
typedef struct
{
    DAQ_Msg_h msg;      // [in] Message belonging to the flow to be modified
    uint8_t *data;      // [in] (SET_FLOW_HA_STATE) / [out] (GET_FLOW_HA_STATE) HA state blob data
    uint32_t length;    // [in] (SET_FLOW_HA_STATE) / [out] (GET_FLOW_HA_STATE) HA state blob size
} DIOCTL_FlowHAState;

/*
 * Command: DIOCTL_SET_FLOW_QOS_ID
 * Description: Set the rule ID on the flow associated with the DAQ message.
 * Argument: DIOCTL_SetFlowQosID
 */
typedef struct
{
    DAQ_Msg_h msg;      // [in] Message belonging to the flow to be modified
    uint64_t qos_id;    // [in] QoS Rule ID (low 32b), QoS Flags (high 32b)
} DIOCTL_SetFlowQosID;

/*
 * Command: DIOCTL_SET_PACKET_TRACE_DATA
 * Description: Add verdict reason and tracing text to the packet associated with the DAQ message.
 * Argument: DIOCTL_SetPacketTraceData
 */
typedef struct
{
    DAQ_Msg_h msg;              // [in] Message to add tracing data to
    uint8_t verdict_reason;     // [in] Magic integer (0-255) reflecting the reason for the application's
                                //  verdict on this message
    uint32_t trace_data_len;    // [in] Tracing data length
    uint8_t *trace_data;        // [in] Tracing data (ASCII text)
} DIOCTL_SetPacketTraceData;

/*
 * Command: DIOCTL_SET_PACKET_VERDICT_REASON
 * Description: Add verdict reason to the packet associated with the DAQ message.
 * Argument: DIOCTL_SetPacketVerdictReason
 */
typedef struct
{
    DAQ_Msg_h msg;              // [in] Message to add verdict reason to
    uint8_t verdict_reason;     // [in] Magic integer (0-255) reflecting the reason for the application's
                                //  verdict on this message
} DIOCTL_SetPacketVerdictReason;

/*
 * Command: DIOCTL_SET_FLOW_PRESERVE
 * Description: Enable preserving the flow associated with the DAQ message when the
 *              application is unavailable.
 * Argument: DAQ_Msg_h (Message belonging to the flow to be modified)
 */

/*
 * Command: DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN
 * Description: Retrieve unmodified TCP options from the SYN for the flow associated with the DAQ message.
 * Argument: DIOCTL_GetFlowScrubbedTcp
 *
 * Command: DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN_ACK
 * Description: Retrieve unmodified TCP options from the SYN-ACK for the flow associated with the DAQ message.
 * Argument: DIOCTL_GetFlowScrubbedTcp
 */
typedef enum
{
    DAQ_TCP_OPTS_MSS_CHANGED = 0x01,
    DAQ_TCP_OPTS_WIN_SCALE_CHANGED = 0x02,
    DAQ_TCP_OPTS_SACK_CHANGED = 0x04,
    DAQ_TCP_OPTS_TS_CHANGED = 0x08,
} DAQ_TCP_Opts_flags_t;

typedef struct
{
    uint8_t flags;                  // DAQ_TCP_OPTS_*
    uint8_t window_scale;
    uint16_t mss;
    uint8_t window_scale_position;
    uint8_t ts_position;
    uint8_t mss_position;
    uint8_t sack_ok_position;
    uint32_t ts_value;
} DAQ_TCP_Opts_t;

typedef struct
{
    DAQ_Msg_h msg;              // [in] Message associated with the flow being queried
    DAQ_TCP_Opts_t *tcp_opts;   // [out] Original TCP options prior to modification by the dataplane
} DIOCTL_GetFlowScrubbedTcp;

/*
 * Command: DIOCTL_CREATE_EXPECTED_FLOW
 * Description: Create an expected flow in the dataplane based on an N-tuple with some optional wildcards.
 * Argument: DIOCTL_CreateExpectedFlow
 */
#define DAQ_EFLOW_TUNNEL_TYPE_NON_TUNNEL    0
#define DAQ_EFLOW_TUNNEL_TYPE_GTP_TUNNEL    1
#define DAQ_EFLOW_TUNNEL_TYPE_MPLS_TUNNEL   2
#define DAQ_EFLOW_TUNNEL_TYPE_OTHER_TUNNEL  3
typedef struct _DAQ_EFlow_Key_t {
    uint16_t src_af;                /* AF_INET or AF_INET6 */
    uint16_t dst_af;                /* AF_INET or AF_INET6 */
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
    uint16_t tunnel_type;       /* Tunnel type (DAQ_DP_TUNNEL_TYPE_*) */
    uint16_t vlan_id;           /* VLAN ID */
    uint16_t vlan_cnots;        /* VLAN ID is a C-Tag (0x8100) rather than an S-Tag (0x8a88) */
} DAQ_EFlow_Key_t;

#define DAQ_EFLOW_FLOAT             0x01 /* the expected flow can float to a different reader */
#define DAQ_EFLOW_ALLOW_MULTIPLE    0x02 /* allow multiple connections to use the same expected flow entry */
#define DAQ_EFLOW_PERSIST           0x04 /* expected flow entry persists even if control channel terminates */
typedef struct _DAQ_EFlow_Setup_t
{
    DAQ_Msg_h ctrl_msg;     // [in] Message containing the companion control channel packet
    DAQ_EFlow_Key_t key;    // [in] Flow key describing the expected flow
    unsigned flags;     /* DAQ_EFLOW_* flags*/
    unsigned timeout_ms;/* timeout of the expected flow entry in milliseconds */
    uint8_t* data;      /* [Future] opaque data blob to return with the expected flow */
    unsigned length;    /* [Future] length of the opaque data blob */
} DIOCTL_CreateExpectedFlow;

#ifdef __cplusplus
}
#endif

#endif /* _DAQ_COMMON_H */

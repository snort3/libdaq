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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/socket.h>
#endif

#include "daq_module_api.h"

#define DAQ_TRACE_VERSION 1

#define DAQ_TRACE_FILENAME "inline-out.txt"

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

#define CHECK_SUBAPI(ctxt, fname) \
    (ctxt->subapi.fname.func != NULL)

#define CALL_SUBAPI_NOARGS(ctxt, fname) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context)

#define CALL_SUBAPI(ctxt, fname, ...) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context, __VA_ARGS__)

typedef struct
{
    DAQ_ModuleInstance_h modinst;
    DAQ_InstanceAPI_t subapi;

    FILE *outfile;
    char *filename;

    DAQ_Stats_t stats;
} TraceContext;

static DAQ_VariableDesc_t trace_variable_descriptions[] = {
    { "file", "Filename to write text traces to (default: " DAQ_TRACE_FILENAME ")", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
};

static DAQ_BaseAPI_t daq_base_api;

//-------------------------------------------------------------------------

static void hexdump(FILE *fp, const uint8_t *data, unsigned int len, const char *prefix)
{
    unsigned int i;
    for (i = 0; i < len; i++)
    {
        if (i % 16 == 0)
            fprintf(fp, "\n%s", prefix ? prefix : "");
        else if (i % 2 == 0)
            fprintf(fp, " ");
        fprintf(fp, "%02x", data[i]);
    }
    fprintf(fp, "\n");
}

static int trace_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int trace_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int trace_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = trace_variable_descriptions;

    return sizeof(trace_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int trace_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    // Simple multi-instance sanity check
    unsigned total_instances = daq_base_api.config_get_total_instances(modcfg);
    unsigned instance_id = daq_base_api.config_get_instance_id(modcfg);
    if (total_instances > 1 && instance_id == 0)
    {
        SET_ERROR(modinst, "%s: Instance ID required for multi-instance (%u instances expected)", __func__, total_instances);
        return DAQ_ERROR_INVAL;
    }

    TraceContext *tc = calloc(1, sizeof(TraceContext));
    if (!tc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the DAQ context", __func__);
        return DAQ_ERROR_NOMEM;
    }
    tc->modinst = modinst;

    if (daq_base_api.resolve_subapi(modinst, &tc->subapi) != DAQ_SUCCESS)
    {
        SET_ERROR(modinst, "%s: Couldn't resolve subapi. No submodule configured?", __func__);
        free(tc);
        return DAQ_ERROR_INVAL;
    }

    const char *filename = DAQ_TRACE_FILENAME;
    const char *varKey, *varValue;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "file"))
            filename = varValue;
        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    // Mangle the output filename with a prefix in the multi-instance scenario
    char prefix[32];
    if (instance_id > 0)
    {
        // For now, only support mangling base filenames (no directory path allowed)
        if (strchr(filename, '/'))
        {
            SET_ERROR(modinst, "%s: Invalid filename for multi-instance: %s", __func__, filename);
            free(tc);
            return DAQ_ERROR_INVAL;
        }

        snprintf(prefix, sizeof(prefix), "%u_", instance_id);
    }
    else
        prefix[0] = '\0';

    size_t len = strlen(filename) + strlen(prefix) + 1;
    tc->filename = malloc(len);
    if (!tc->filename)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the text output filename", __func__);
        free(tc);
        return DAQ_ERROR_NOMEM;
    }
    snprintf(tc->filename, len, "%s%s", prefix, filename);

    *ctxt_ptr = tc;

    return DAQ_SUCCESS;
}

static void trace_daq_destroy(void *handle)
{
    TraceContext *tc = (TraceContext *) handle;

    if (tc->outfile)
        fclose(tc->outfile);
    free(tc->filename);
    free(tc);
}

static int trace_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    TraceContext *tc = (TraceContext*) handle;

    if (type == DAQ_MSG_TYPE_PACKET)
    {
        const DAQ_PktHdr_t *pkthdr = (const DAQ_PktHdr_t *) hdr;
        fprintf(tc->outfile, "I: %lu.%lu(%u)\n", (unsigned long) pkthdr->ts.tv_sec,
               (unsigned long) pkthdr->ts.tv_usec, data_len);
        hexdump(tc->outfile, data, data_len, "    ");
        fprintf(tc->outfile, "\n");
    }

    if (CHECK_SUBAPI(tc, inject))
    {
        int rval = CALL_SUBAPI(tc, inject, type, hdr, data, data_len);
        if (rval != DAQ_SUCCESS)
            return rval;
    }

    tc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int trace_daq_inject_relative(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    TraceContext *tc = (TraceContext*) handle;
    const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;

    fprintf(tc->outfile, "%cI: %lu.%lu(%u): %u\n", reverse ? 'R' : 'F',
            (unsigned long) hdr->ts.tv_sec, (unsigned long) hdr->ts.tv_usec, msg->data_len, data_len);
    hexdump(tc->outfile, data, data_len, "    ");
    fprintf(tc->outfile, "\n");

    if (CHECK_SUBAPI(tc, inject_relative))
    {
        int rval = CALL_SUBAPI(tc, inject_relative, msg, data, data_len, reverse);
        if (rval != DAQ_SUCCESS)
            return rval;
    }

    tc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int trace_daq_start(void* handle)
{
    TraceContext *tc = (TraceContext*) handle;

    int rval = CALL_SUBAPI_NOARGS(tc, start);
    if (rval != DAQ_SUCCESS)
        return rval;

    const char* filename = tc->filename ? tc->filename : DAQ_TRACE_FILENAME;
    tc->outfile = fopen(filename, "w");
    if (!tc->outfile)
    {
        CALL_SUBAPI_NOARGS(tc, stop);
        SET_ERROR(tc->modinst, "can't open text output file");
        return DAQ_ERROR;
    }

    return DAQ_SUCCESS;
}

static int trace_daq_stop (void* handle)
{
    TraceContext *tc = (TraceContext*) handle;
    int rval = CALL_SUBAPI_NOARGS(tc, stop);

    if (rval != DAQ_SUCCESS)
        return rval;

    if (tc->outfile)
    {
        fclose(tc->outfile);
        tc->outfile = NULL;
    }

    return DAQ_SUCCESS;
}

static void print_msg(TraceContext* tc, const DAQ_Msg_t *msg)
{
    if (msg->type == DAQ_MSG_TYPE_PACKET)
    {
        const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;
        fprintf(tc->outfile, "%lu.%lu(%u)", (unsigned long) hdr->ts.tv_sec,
                    (unsigned long) hdr->ts.tv_usec, msg->data_len);
    }
}

static int trace_daq_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    TraceContext* tc = (TraceContext*) handle;

    switch (cmd)
    {
        case DIOCTL_GET_DEVICE_INDEX:
        {
            if (arglen != sizeof(DIOCTL_QueryDeviceIndex))
                return DAQ_ERROR_INVAL;
            DIOCTL_QueryDeviceIndex *qdi = (DIOCTL_QueryDeviceIndex *) arg;
            if (!qdi->device)
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: QueryDeviceIndex: '%s'\n", qdi->device);
            break;
        }
        case DIOCTL_SET_FLOW_OPAQUE:
        {
            if (arglen != sizeof(DIOCTL_SetFlowOpaque))
                return DAQ_ERROR_INVAL;
            DIOCTL_SetFlowOpaque *sfo = (DIOCTL_SetFlowOpaque *) arg;
            if (!sfo->msg)
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: SetFlowOpaque: ");
            print_msg(tc, sfo->msg);
            fprintf(tc->outfile, " Value: %u\n", sfo->value);
            break;
        }
        case DIOCTL_SET_FLOW_HA_STATE:
        {
            if (arglen != sizeof(DIOCTL_FlowHAState))
                return DAQ_ERROR_INVAL;
            DIOCTL_FlowHAState *fhs = (DIOCTL_FlowHAState *) arg;
            if (!fhs->msg || (!fhs->data && fhs->length != 0))
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: SetFlowHAState: ");
            print_msg(tc, fhs->msg);
            fprintf(tc->outfile, " (%u)\n", fhs->length);
            hexdump(tc->outfile, fhs->data, fhs->length, "    ");
            break;
        }
        case DIOCTL_GET_FLOW_HA_STATE:
        {
            if (arglen != sizeof(DIOCTL_FlowHAState))
                return DAQ_ERROR_INVAL;
            DIOCTL_FlowHAState *fhs = (DIOCTL_FlowHAState *) arg;
            if (!fhs->msg)
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: GetFlowHAState: ");
            print_msg(tc, fhs->msg);
            fprintf(tc->outfile, "\n");
            break;
        }
        case DIOCTL_SET_FLOW_QOS_ID:
        {
            if (arglen != sizeof(DIOCTL_SetFlowQosID))
                return DAQ_ERROR_INVAL;
            DIOCTL_SetFlowQosID *sfq = (DIOCTL_SetFlowQosID *) arg;
            if (!sfq->msg)
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: SetFlowQosID: ");
            print_msg(tc, sfq->msg);
            fprintf(tc->outfile, "%u/0x%x\n", (unsigned) (sfq->qos_id & 0xFFFFFFFF),
                    (unsigned) (sfq->qos_id >> 32));
            break;
        }
        case DIOCTL_SET_PACKET_TRACE_DATA:
        {
            if (arglen != sizeof(DIOCTL_SetPacketTraceData))
                return DAQ_ERROR_INVAL;
            DIOCTL_SetPacketTraceData *sptd = (DIOCTL_SetPacketTraceData *) arg;
            if (!sptd->msg || (!sptd->trace_data && sptd->trace_data_len != 0))
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: SetPacketTraceData: ");
            print_msg(tc, sptd->msg);
            fprintf(tc->outfile, " VR: %hhu (%u):\n", sptd->verdict_reason, sptd->trace_data_len);
            fprintf(tc->outfile, "    %.*s\n", sptd->trace_data_len, sptd->trace_data);
            break;
        }
        case DIOCTL_SET_PACKET_VERDICT_REASON:
        {
            if (arglen != sizeof(DIOCTL_SetPacketVerdictReason))
                return DAQ_ERROR_INVAL;
            DIOCTL_SetPacketVerdictReason *spvr = (DIOCTL_SetPacketVerdictReason *) arg;
            if (!spvr->msg)
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: SetPacketVerdictReason: ");
            print_msg(tc, spvr->msg);
            fprintf(tc->outfile, " VR: %hhu\n", spvr->verdict_reason);
            break;
        }
        case DIOCTL_SET_FLOW_PRESERVE:
        {
            if (arglen != sizeof(DAQ_Msg_h))
                return DAQ_ERROR_INVAL;
            DAQ_Msg_h msg = (DAQ_Msg_h) arg;
            if (!msg)
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: SetFlowPreserve: ");
            print_msg(tc, msg);
            fprintf(tc->outfile, "\n");
            break;
        }
        case DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN:
        case DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN_ACK:
        {
            if (arglen != sizeof(DIOCTL_GetFlowScrubbedTcp))
                return DAQ_ERROR_INVAL;
            DIOCTL_GetFlowScrubbedTcp *gpst = (DIOCTL_GetFlowScrubbedTcp *) arg;
            if (!gpst->msg)
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: %s: ", (cmd == DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN) ?
                    "GetFlowTcpScrubbedSyn" : "GetFlowTcpScrubbedSynAck");
            print_msg(tc, gpst->msg);
            fprintf(tc->outfile, "\n");
            break;
        }
        case DIOCTL_CREATE_EXPECTED_FLOW:
        {
            if (arglen != sizeof(DIOCTL_CreateExpectedFlow))
                return DAQ_ERROR_INVAL;
            DIOCTL_CreateExpectedFlow *cef = (DIOCTL_CreateExpectedFlow *) arg;
            if (!cef->ctrl_msg || cef->ctrl_msg->type != DAQ_MSG_TYPE_PACKET)
                return DAQ_ERROR_INVAL;
            fprintf(tc->outfile, "IOCTL: CreateExpectedFlow: ");
            print_msg(tc, cef->ctrl_msg);
            fprintf(tc->outfile, ":\n");

            DAQ_EFlow_Key_t *key = (DAQ_EFlow_Key_t *) &cef->key;
            char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN];
            if (key->src_af == AF_INET)
                inet_ntop(AF_INET, &key->sa.src_ip4, src_addr_str, sizeof(src_addr_str));
            else
                inet_ntop(AF_INET6, &key->sa.src_ip6, src_addr_str, sizeof(src_addr_str));
            if (key->dst_af == AF_INET)
                inet_ntop(AF_INET, &key->da.dst_ip4, dst_addr_str, sizeof(dst_addr_str));
            else
                inet_ntop(AF_INET6, &key->da.dst_ip6, dst_addr_str, sizeof(dst_addr_str));
            fprintf(tc->outfile, "    %s:%hu -> %s:%hu (%hhu)\n", src_addr_str, key->src_port,
                    dst_addr_str, key->dst_port, key->protocol);
            fprintf(tc->outfile, "    %u %hu %hu %hu 0x%X %u\n", key->address_space_id, key->tunnel_type,
                    key->vlan_id, key->vlan_cnots, cef->flags, cef->timeout_ms);
            break;
        }
        case DIOCTL_DIRECT_INJECT_PAYLOAD:
        {
            if (arglen != sizeof(DIOCTL_DirectInjectPayload))
                return DAQ_ERROR_INVAL;
            DIOCTL_DirectInjectPayload *dip = (DIOCTL_DirectInjectPayload *) arg;
            fprintf(tc->outfile, "IOCTL: DirectInjectPayload: ");
            print_msg(tc, dip->msg);
            fprintf(tc->outfile, " (%hhu segments)%s\n", dip->num_segments, dip->reverse ? " (reverse)" : "");
            for (int i = 0; i < dip->num_segments; i++)
            {
                const DAQ_DIPayloadSegment *segment = dip->segments[i];
                fprintf(tc->outfile, "  Segment %d (%u)\n", i, segment->length);
                hexdump(tc->outfile, segment->data, segment->length, "    ");
            }
            break;
        }
        case DIOCTL_DIRECT_INJECT_RESET:
        {
            if (arglen != sizeof(DIOCTL_DirectInjectReset))
                return DAQ_ERROR_INVAL;
            DIOCTL_DirectInjectReset *dir = (DIOCTL_DirectInjectReset *) arg;
            fprintf(tc->outfile, "IOCTL: DirectInjectReset: ");
            print_msg(tc, dir->msg);
            if (dir->direction == DAQ_DIR_BOTH)
                fprintf(tc->outfile, " (both)");
            else if (dir->direction == DAQ_DIR_REVERSE)
                fprintf(tc->outfile, " (reverse)");
            fprintf(tc->outfile, "\n");
            break;
        }
        case DIOCTL_GET_PRIV_DATA_LEN:
        {
            break;
        }

        default:
            fprintf(tc->outfile, "IOCTL: %d (%zu)\n", cmd, arglen);
            hexdump(tc->outfile, arg, arglen, "    ");
            break;
    }

    if (CHECK_SUBAPI(tc, ioctl))
        return CALL_SUBAPI(tc, ioctl, cmd, arg, arglen);

    return DAQ_SUCCESS;
}

static int trace_daq_get_stats(void* handle, DAQ_Stats_t* stats)
{
    TraceContext *tc = (TraceContext*) handle;
    int rval = DAQ_SUCCESS;

    if (CHECK_SUBAPI(tc, get_stats))
    {
        rval = CALL_SUBAPI(tc, get_stats, stats);
        /* Use our own concept of verdict and injected packet stats */
        for (int i = 0; i < MAX_DAQ_VERDICT; i++)
            stats->verdicts[i] = tc->stats.verdicts[i];
        stats->packets_injected = tc->stats.packets_injected;
    }
    else
        *stats = tc->stats;

    return rval;
}

static void trace_daq_reset_stats(void* handle)
{
    TraceContext *tc = (TraceContext*) handle;
    if (CHECK_SUBAPI(tc, reset_stats))
        CALL_SUBAPI_NOARGS(tc, reset_stats);
    memset(&tc->stats, 0, sizeof(tc->stats));
}

static uint32_t trace_daq_get_capabilities(void* handle)
{
    TraceContext *tc = (TraceContext*) handle;
    uint32_t caps = CHECK_SUBAPI(tc, get_capabilities) ? CALL_SUBAPI_NOARGS(tc, get_capabilities) : 0;
    caps |= DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT;
    return caps;
}

// We don't have access to daq_verdict_string() because we're not linking
// against LibDAQ, so pack our own copy.
static const char *daq_verdict_strings[MAX_DAQ_VERDICT] = {
    "Pass",         // DAQ_VERDICT_PASS
    "Block",        // DAQ_VERDICT_BLOCK
    "Replace",      // DAQ_VERDICT_REPLACE
    "Whitelist",    // DAQ_VERDICT_WHITELIST
    "Blacklist",    // DAQ_VERDICT_BLACKLIST
    "Ignore"        // DAQ_VERDICT_IGNORE
};

static int trace_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    TraceContext *tc = (TraceContext *) handle;

    tc->stats.verdicts[verdict]++;
    if (msg->type == DAQ_MSG_TYPE_PACKET)
    {
        DAQ_PktHdr_t *hdr = (DAQ_PktHdr_t *) msg->hdr;
        const uint8_t *data = msg->data;

        fprintf(tc->outfile, "PV: %lu.%lu(%u): %s\n", (unsigned long) hdr->ts.tv_sec,
                (unsigned long) hdr->ts.tv_usec, msg->data_len, daq_verdict_strings[verdict]);
        if (verdict == DAQ_VERDICT_REPLACE)
            hexdump(tc->outfile, data, msg->data_len, "    ");
    }

    return CALL_SUBAPI(tc, msg_finalize, msg, verdict);
}

//-------------------------------------------------------------------------

#ifdef BUILDING_SO
DAQ_SO_PUBLIC DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
DAQ_ModuleAPI_t trace_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_TRACE_VERSION,
    /* .name = */ "trace",
    /* .type = */ DAQ_TYPE_WRAPPER | DAQ_TYPE_INLINE_CAPABLE,
    /* .load = */ trace_daq_module_load,
    /* .unload = */ trace_daq_module_unload,
    /* .get_variable_descs = */ trace_daq_get_variable_descs,
    /* .instantiate = */ trace_daq_instantiate,
    /* .destroy = */ trace_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ trace_daq_start,
    /* .inject = */ trace_daq_inject,
    /* .inject_relative = */ trace_daq_inject_relative,
    /* .interrupt = */ NULL,
    /* .stop = */ trace_daq_stop,
    /* .ioctl = */ trace_daq_ioctl,
    /* .get_stats = */ trace_daq_get_stats,
    /* .reset_stats = */ trace_daq_reset_stats,
    /* .get_snaplen = */ NULL,
    /* .get_capabilities = */ trace_daq_get_capabilities,
    /* .get_datalink_type = */ NULL,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ NULL,
    /* .msg_finalize = */ trace_daq_msg_finalize,
    /* .get_msg_pool_info = */ NULL,
};


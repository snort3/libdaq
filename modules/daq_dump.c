/****************************************************************************
 *
 * Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/socket.h>
#endif

#include "daq.h"
#include "daq_api.h"

#define DAQ_DUMP_VERSION 4

#define DAQ_DUMP_PCAP_FILE "inline-out.pcap"
#define DAQ_DUMP_TEXT_FILE "inline-out.txt"

typedef enum {
    DUMP_OUTPUT_NONE = 0x0,
    DUMP_OUTPUT_PCAP = 0x1,
    DUMP_OUTPUT_TEXT = 0x2,
    DUMP_OUTPUT_BOTH = 0x3
} DumpOutputType;

typedef struct
{
    // delegate most stuff to the wrapped module
    const DAQ_ModuleAPI_t *wrapped_module;
    void *wrapped_context;

    // but write all output packets here
    pcap_dumper_t *dump;
    char *pcap_filename;

    // and write other textual output here
    FILE *text_out;
    char* text_filename;

    DumpOutputType output_type;

    DAQ_Stats_t stats;
} DumpContext;

static DAQ_VariableDesc_t dump_variable_descriptions[] = {
    { "file", "PCAP filename to output transmitted packets to", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "text-file", "Filename for text output representing transmitted packets", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "output", "Type of output to generate (none, pcap, text, or both)", DAQ_VAR_DESC_REQUIRES_ARGUMENT }
};

DAQ_BaseAPI_t daq_base_api;


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

static int dump_daq_prepare(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int dump_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = dump_variable_descriptions;

    return sizeof(dump_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int dump_daq_initialize(const DAQ_ModuleConfig_h config, void **ctxt_ptr, char *errBuf, size_t errMax)
{
    DAQ_ModuleConfig_h subconfig;
    DumpContext *dc;
    const char *varKey, *varValue;
    int rval;

    subconfig = daq_base_api.module_config_get_next(config);
    if (!subconfig)
    {
        snprintf(errBuf, errMax, "%s: No submodule configuration provided", __func__);
        return DAQ_ERROR_INVAL;
    }

    dc = calloc(1, sizeof(DumpContext));
    if (!dc)
    {
        snprintf(errBuf, errMax, "%s: Couldn't allocate memory for the DAQ context", __func__);
        return DAQ_ERROR_NOMEM;
    }
    dc->output_type = DUMP_OUTPUT_PCAP;

    daq_base_api.module_config_first_variable(config, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "file"))
        {
            dc->pcap_filename = strdup(varValue);
            if (!dc->pcap_filename)
            {
                snprintf(errBuf, errMax, "%s: Couldn't allocate memory for the PCAP output filename", __func__);
                free(dc);
                return DAQ_ERROR_NOMEM;
            }
        }
        else if (!strcmp(varKey, "text-file"))
        {
            dc->text_filename = strdup(varValue);
            if (!dc->text_filename)
            {
                snprintf(errBuf, errMax, "%s: Couldn't allocate memory for the text output filename", __func__);
                free(dc);
                return DAQ_ERROR_NOMEM;
            }
        }
        else if (!strcmp(varKey, "output"))
        {
            if (!strcmp(varValue, "none"))
                dc->output_type = DUMP_OUTPUT_NONE;
            else if (!strcmp(varValue, "pcap"))
                dc->output_type = DUMP_OUTPUT_PCAP;
            else if (!strcmp(varValue, "text"))
                dc->output_type = DUMP_OUTPUT_TEXT;
            else if (!strcmp(varValue, "both"))
                dc->output_type = DUMP_OUTPUT_BOTH;
            else
            {
                snprintf(errBuf, errMax, "%s: Invalid output type (%s)", __func__, varValue);
                free(dc);
                return DAQ_ERROR_INVAL;
            }
        }
        daq_base_api.module_config_next_variable(config, &varKey, &varValue);
    }

    dc->wrapped_module = daq_base_api.module_config_get_module(subconfig);
    rval = dc->wrapped_module->initialize(subconfig, &dc->wrapped_context, errBuf, errMax);
    if (rval != DAQ_SUCCESS)
    {
        if (dc->pcap_filename)
            free(dc->pcap_filename);
        if (dc->text_filename)
            free(dc->text_filename);
        free(dc);
        return rval;
    }

    *ctxt_ptr = dc;

    return DAQ_SUCCESS;
}

static void dump_daq_shutdown (void *handle)
{
    DumpContext *dc = (DumpContext *) handle;

    dc->wrapped_module->shutdown(dc->wrapped_context);
    if (dc->pcap_filename)
        free(dc->pcap_filename);
    if (dc->text_filename)
        free(dc->text_filename);
    free(dc);
}

static int dump_daq_inject (void *handle, const DAQ_PktHdr_t* hdr, const uint8_t* data, uint32_t len, int reverse)
{
    DumpContext *dc = (DumpContext*)handle;

    if (dc->text_out)
    {
        fprintf(dc->text_out, "%cI: %lu.%lu(%u): %u\n", reverse ? 'R' : 'F',
                (unsigned long) hdr->ts.tv_sec, (unsigned long) hdr->ts.tv_usec, hdr->caplen, len);
        hexdump(dc->text_out, data, len, "    ");
        fprintf(dc->text_out, "\n");
    }

    if (dc->dump)
    {
        // copy the original header to get the same
        // timestamps but overwrite the lengths
        DAQ_PktHdr_t h = *hdr;

        h.pktlen = h.caplen = len;
        pcap_dump((u_char*)dc->dump, (struct pcap_pkthdr*)&h, data);

        if (ferror(pcap_dump_file(dc->dump)))
        {
            dc->wrapped_module->set_errbuf(dc->wrapped_context, "inject can't write to dump file");
            return DAQ_ERROR;
        }
    }
    dc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int dump_daq_start(void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    int dlt, snaplen, rval;

    rval = dc->wrapped_module->start(dc->wrapped_context);
    if (rval != DAQ_SUCCESS)
        return rval;

    dlt = dc->wrapped_module->get_datalink_type(dc->wrapped_context);
    snaplen = dc->wrapped_module->get_snaplen(dc->wrapped_context);

    if (dc->output_type & DUMP_OUTPUT_PCAP)
    {
        const char* pcap_filename = dc->pcap_filename ? dc->pcap_filename : DAQ_DUMP_PCAP_FILE;
        pcap_t* pcap;

        pcap = pcap_open_dead(dlt, snaplen);
        dc->dump = pcap ? pcap_dump_open(pcap, pcap_filename) : NULL;
        if (!dc->dump)
        {
            dc->wrapped_module->stop(dc->wrapped_context);
            dc->wrapped_module->set_errbuf(dc->wrapped_context, "can't open dump file");
            return DAQ_ERROR;
        }
        pcap_close(pcap);
    }

    if (dc->output_type & DUMP_OUTPUT_TEXT)
    {
        const char* text_filename = dc->text_filename ? dc->text_filename : DAQ_DUMP_TEXT_FILE;

        dc->text_out = fopen(text_filename, "w");
        if (!dc->text_out)
        {
            dc->wrapped_module->stop(dc->wrapped_context);
            dc->wrapped_module->set_errbuf(dc->wrapped_context, "can't open text output file");
            return DAQ_ERROR;
        }
    }

    return DAQ_SUCCESS;
}

static int dump_daq_stop (void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    int err = dc->wrapped_module->stop(dc->wrapped_context);

    if (err)
        return err;

    if (dc->dump)
    {
        pcap_dump_close(dc->dump);
        dc->dump = NULL;
    }

    if (dc->text_out)
    {
        fclose(dc->text_out);
        dc->text_out = NULL;
    }

    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------
// these methods are delegated to the pcap daq

static int dump_daq_set_filter (void* handle, const char* filter)
{
    DumpContext *dc = (DumpContext*)handle;
    return dc->wrapped_module->set_filter(dc->wrapped_context, filter);
}

static int dump_daq_breakloop (void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    return dc->wrapped_module->breakloop(dc->wrapped_context);
}

static DAQ_State dump_daq_check_status (void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    return dc->wrapped_module->check_status(dc->wrapped_context);
}

static int dump_daq_get_stats (void* handle, DAQ_Stats_t* stats)
{
    DumpContext *dc = (DumpContext*)handle;
    int ret = dc->wrapped_module->get_stats(dc->wrapped_context, stats);
    int i;

    for (i = 0; i < MAX_DAQ_VERDICT; i++)
        stats->verdicts[i] = dc->stats.verdicts[i];

    stats->packets_injected = dc->stats.packets_injected;
    return ret;
}

static void dump_daq_reset_stats (void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    dc->wrapped_module->reset_stats(dc->wrapped_context);
    memset(&dc->stats, 0, sizeof(dc->stats));
}

static int dump_daq_get_snaplen (void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    return dc->wrapped_module->get_snaplen(dc->wrapped_context);
}

static uint32_t dump_daq_get_capabilities (void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    uint32_t caps = dc->wrapped_module->get_capabilities(dc->wrapped_context);
    caps |= DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT;
    return caps;
}

static int dump_daq_get_datalink_type (void *handle)
{
    DumpContext *dc = (DumpContext *) handle;

    return dc->wrapped_module->get_datalink_type(dc->wrapped_context);
}

static const char* dump_daq_get_errbuf (void* handle)
{
    DumpContext *dc = (DumpContext *) handle;

    return dc->wrapped_module->get_errbuf(dc->wrapped_context);
}

static void dump_daq_set_errbuf (void* handle, const char* s)
{
    DumpContext *dc = (DumpContext *) handle;

    dc->wrapped_module->set_errbuf(dc->wrapped_context, s ? s : "");
}

static int dump_daq_get_device_index(void *handle, const char *device)
{
    DumpContext *dc = (DumpContext *) handle;

    return dc->wrapped_module->get_device_index(dc->wrapped_context, device);
}

static int dump_daq_modify_flow(void *handle, const DAQ_PktHdr_t *hdr, const DAQ_ModFlow_t *modify)
{
    DumpContext* dc = (DumpContext*)handle;

    if (dc->text_out)
    {
        fprintf(dc->text_out, "MF: %lu.%lu(%u): %d %u \n", (unsigned long) hdr->ts.tv_sec,
                (unsigned long) hdr->ts.tv_usec, hdr->caplen, modify->type, modify->length);
        hexdump(dc->text_out, modify->value, modify->length, "    ");
    }
    return DAQ_SUCCESS;
}

static int dump_daq_dp_add_dc(void *handle, const DAQ_PktHdr_t *hdr, DAQ_DP_key_t *dp_key,
                                const uint8_t *packet_data, DAQ_Data_Channel_Params_t *params)
{
    DumpContext* dc = (DumpContext*)handle;

    if (dc->text_out)
    {
        char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN];

        fprintf(dc->text_out, "DP: %lu.%lu(%u):\n", (unsigned long) hdr->ts.tv_sec,
                (unsigned long) hdr->ts.tv_usec, hdr->caplen);
        if (dp_key->src_af == AF_INET)
            inet_ntop(AF_INET, &dp_key->sa.src_ip4, src_addr_str, sizeof(src_addr_str));
        else
            inet_ntop(AF_INET6, &dp_key->sa.src_ip6, src_addr_str, sizeof(src_addr_str));
        if (dp_key->dst_af == AF_INET)
            inet_ntop(AF_INET, &dp_key->da.dst_ip4, dst_addr_str, sizeof(dst_addr_str));
        else
            inet_ntop(AF_INET6, &dp_key->da.dst_ip6, dst_addr_str, sizeof(dst_addr_str));
        fprintf(dc->text_out, "    %s:%hu -> %s:%hu (%hhu)\n", src_addr_str, dp_key->src_port,
                dst_addr_str, dp_key->dst_port, dp_key->protocol);
        fprintf(dc->text_out, "    %hu %hu %hu %hu 0x%X %u\n", dp_key->address_space_id, dp_key->tunnel_type,
                dp_key->vlan_id, dp_key->vlan_cnots, params ? params->flags : 0, params ? params->timeout_ms : 0);
    }
    return DAQ_SUCCESS;
}

static unsigned dump_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    DumpContext *dc = (DumpContext *) handle;

    return dc->wrapped_module->msg_receive(dc->wrapped_context, max_recv, msgs, rstat);
}

static const int s_fwd[MAX_DAQ_VERDICT] = { 1, 0, 1, 1, 0, 1, 0 };
// We don't have access to daq_verdict_string() because we're not linking
// against LibDAQ, so pack our own copy.
static const char *daq_verdict_strings[MAX_DAQ_VERDICT] = {
    "Pass",         // DAQ_VERDICT_PASS
    "Block",        // DAQ_VERDICT_BLOCK
    "Replace",      // DAQ_VERDICT_REPLACE
    "Whitelist",    // DAQ_VERDICT_WHITELIST
    "Blacklist",    // DAQ_VERDICT_BLACKLIST
    "Ignore",       // DAQ_VERDICT_IGNORE
    "Retry"         // DAQ_VERDICT_RETRY
};

static int dump_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    DumpContext *dc = (DumpContext *) handle;

    dc->stats.verdicts[verdict]++;
    if (msg->type == DAQ_MSG_TYPE_PACKET)
    {
        DAQ_PktHdr_t *hdr = dc->wrapped_module->packet_header_from_msg(dc->wrapped_context, msg);
        const uint8_t *data = dc->wrapped_module->packet_data_from_msg(dc->wrapped_context, msg);

        if (dc->dump && s_fwd[verdict])
        {
            struct pcap_pkthdr pcap_hdr;

            pcap_hdr.ts = hdr->ts;
            pcap_hdr.caplen = hdr->caplen;
            pcap_hdr.len = hdr->pktlen;
            pcap_dump((u_char *) dc->dump, &pcap_hdr, data);
        }

        if (dc->text_out)
        {
            fprintf(dc->text_out, "PV: %lu.%lu(%u): %s\n", (unsigned long) hdr->ts.tv_sec,
                    (unsigned long) hdr->ts.tv_usec, hdr->caplen, daq_verdict_strings[verdict]);
            if (verdict == DAQ_VERDICT_REPLACE)
                hexdump(dc->text_out, data, hdr->caplen, "    ");
        }
    }

    return dc->wrapped_module->msg_finalize(dc->wrapped_context, msg, verdict);
}

static DAQ_PktHdr_t *dump_daq_packet_header_from_msg(void *handle, const DAQ_Msg_t *msg)
{
    DumpContext *dc = (DumpContext *) handle;

    return dc->wrapped_module->packet_header_from_msg(dc->wrapped_context, msg);
}

static const uint8_t *dump_daq_packet_data_from_msg(void *handle, const DAQ_Msg_t *msg)
{
    DumpContext *dc = (DumpContext *) handle;

    return dc->wrapped_module->packet_data_from_msg(dc->wrapped_context, msg);
}

//-------------------------------------------------------------------------

#ifdef BUILDING_SO
DAQ_SO_PUBLIC DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
DAQ_ModuleAPI_t dump_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_DUMP_VERSION,
    /* .name = */ "dump",
    /* .type = */ DAQ_TYPE_WRAPPER | DAQ_TYPE_INLINE_CAPABLE,
    /* .prepare = */ dump_daq_prepare,
    /* .get_variable_descs = */ dump_daq_get_variable_descs,
    /* .initialize = */ dump_daq_initialize,
    /* .set_filter = */ dump_daq_set_filter,
    /* .start = */ dump_daq_start,
    /* .inject = */ dump_daq_inject,
    /* .breakloop = */ dump_daq_breakloop,
    /* .stop = */ dump_daq_stop,
    /* .shutdown = */ dump_daq_shutdown,
    /* .check_status = */ dump_daq_check_status,
    /* .get_stats = */ dump_daq_get_stats,
    /* .reset_stats = */ dump_daq_reset_stats,
    /* .get_snaplen = */ dump_daq_get_snaplen,
    /* .get_capabilities = */ dump_daq_get_capabilities,
    /* .get_datalink_type = */ dump_daq_get_datalink_type,
    /* .get_errbuf = */ dump_daq_get_errbuf,
    /* .set_errbuf = */ dump_daq_set_errbuf,
    /* .get_device_index = */ dump_daq_get_device_index,
    /* .modify_flow = */ dump_daq_modify_flow,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ dump_daq_dp_add_dc,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ dump_daq_msg_receive,
    /* .msg_finalize = */ dump_daq_msg_finalize,
    /* .packet_header_from_msg = */ dump_daq_packet_header_from_msg,
    /* .packet_data_from_msg = */ dump_daq_packet_data_from_msg
};


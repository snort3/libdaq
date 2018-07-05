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

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

#define CALL_SUBAPI_NOARGS(ctxt, fname) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context)

#define CALL_SUBAPI(ctxt, fname, ...) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context, __VA_ARGS__)

typedef enum {
    DUMP_OUTPUT_NONE = 0x0,
    DUMP_OUTPUT_PCAP = 0x1,
    DUMP_OUTPUT_TEXT = 0x2,
    DUMP_OUTPUT_BOTH = 0x3
} DumpOutputType;

typedef struct
{
    DAQ_ModuleInstance_h modinst;

    // delegate most stuff to downstream
    DAQ_InstanceAPI_t subapi;

    // but write all output packets here
    pcap_dumper_t *dumper;
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

static int dump_daq_initialize(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    DAQ_ModuleConfig_h subconfig;
    DumpContext *dc;
    const char *varKey, *varValue;
    int rval;

    subconfig = daq_base_api.config_get_next(modcfg);
    if (!subconfig)
    {
        SET_ERROR(modinst, "%s: No submodule configuration provided", __func__);
        return DAQ_ERROR_INVAL;
    }

    dc = calloc(1, sizeof(DumpContext));
    if (!dc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the DAQ context", __func__);
        return DAQ_ERROR_NOMEM;
    }
    dc->modinst = modinst;
    dc->output_type = DUMP_OUTPUT_PCAP;

    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "file"))
        {
            dc->pcap_filename = strdup(varValue);
            if (!dc->pcap_filename)
            {
                SET_ERROR(modinst, "%s: Couldn't allocate memory for the PCAP output filename", __func__);
                free(dc);
                return DAQ_ERROR_NOMEM;
            }
        }
        else if (!strcmp(varKey, "text-file"))
        {
            dc->text_filename = strdup(varValue);
            if (!dc->text_filename)
            {
                SET_ERROR(modinst, "%s: Couldn't allocate memory for the text output filename", __func__);
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
                SET_ERROR(modinst, "%s: Invalid output type (%s)", __func__, varValue);
                free(dc);
                return DAQ_ERROR_INVAL;
            }
        }
        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    rval = daq_base_api.instantiate_submodule(modinst, subconfig);
    if (rval != DAQ_SUCCESS)
    {
        if (dc->pcap_filename)
            free(dc->pcap_filename);
        if (dc->text_filename)
            free(dc->text_filename);
        free(dc);
        return rval;
    }
    daq_base_api.resolve_subapi(modinst, &dc->subapi);

    *ctxt_ptr = dc;

    return DAQ_SUCCESS;
}

static void dump_daq_shutdown(void *handle)
{
    DumpContext *dc = (DumpContext *) handle;

    CALL_SUBAPI_NOARGS(dc, shutdown);
    if (dc->pcap_filename)
        free(dc->pcap_filename);
    if (dc->text_filename)
        free(dc->text_filename);
    free(dc);
}

static int dump_daq_inject(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t len, int reverse)
{
    DumpContext *dc = (DumpContext*) handle;
    const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;

    if (dc->text_out)
    {
        fprintf(dc->text_out, "%cI: %lu.%lu(%u): %u\n", reverse ? 'R' : 'F',
                (unsigned long) hdr->ts.tv_sec, (unsigned long) hdr->ts.tv_usec, msg->data_len, len);
        hexdump(dc->text_out, data, len, "    ");
        fprintf(dc->text_out, "\n");
    }

    if (dc->dumper)
    {
        struct pcap_pkthdr phdr;

        // Reuse the timestamp from the original packet for the injected packet
        phdr.ts = hdr->ts;
        phdr.caplen = len;
        phdr.len = len;

        pcap_dump((u_char*)dc->dumper, &phdr, data);

        if (ferror(pcap_dump_file(dc->dumper)))
        {
            SET_ERROR(dc->modinst, "inject can't write to dump file");
            return DAQ_ERROR;
        }
    }
    dc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int dump_daq_start(void* handle)
{
    DumpContext *dc = (DumpContext*) handle;

    int rval = CALL_SUBAPI_NOARGS(dc, start);
    if (rval != DAQ_SUCCESS)
        return rval;

    int dlt = CALL_SUBAPI_NOARGS(dc, get_datalink_type);
    int snaplen = CALL_SUBAPI_NOARGS(dc, get_snaplen);

    if (dc->output_type & DUMP_OUTPUT_PCAP)
    {
        const char* pcap_filename = dc->pcap_filename ? dc->pcap_filename : DAQ_DUMP_PCAP_FILE;
        pcap_t* pcap;

        pcap = pcap_open_dead(dlt, snaplen);
        dc->dumper = pcap ? pcap_dump_open(pcap, pcap_filename) : NULL;
        if (!dc->dumper)
        {
            CALL_SUBAPI_NOARGS(dc, stop);
            SET_ERROR(dc->modinst, "can't open dump file");
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
            CALL_SUBAPI_NOARGS(dc, stop);
            SET_ERROR(dc->modinst, "can't open text output file");
            return DAQ_ERROR;
        }
    }

    return DAQ_SUCCESS;
}

static int dump_daq_stop (void* handle)
{
    DumpContext *dc = (DumpContext*) handle;
    int rval = CALL_SUBAPI_NOARGS(dc, stop);

    if (rval != DAQ_SUCCESS)
        return rval;

    if (dc->dumper)
    {
        pcap_dump_close(dc->dumper);
        dc->dumper = NULL;
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

static int dump_daq_get_stats(void* handle, DAQ_Stats_t* stats)
{
    DumpContext *dc = (DumpContext*) handle;
    int rval = CALL_SUBAPI(dc, get_stats, stats);

    /* Use our own concept of verdict and injected packet stats */
    for (int i = 0; i < MAX_DAQ_VERDICT; i++)
        stats->verdicts[i] = dc->stats.verdicts[i];
    stats->packets_injected = dc->stats.packets_injected;

    return rval;
}

static void dump_daq_reset_stats(void* handle)
{
    DumpContext *dc = (DumpContext*) handle;
    CALL_SUBAPI_NOARGS(dc, reset_stats);
    memset(&dc->stats, 0, sizeof(dc->stats));
}

static uint32_t dump_daq_get_capabilities(void* handle)
{
    DumpContext *dc = (DumpContext*) handle;
    uint32_t caps = CALL_SUBAPI_NOARGS(dc, get_capabilities);
    caps |= DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT;
    return caps;
}

static int dump_daq_modify_flow(void *handle, const DAQ_Msg_t *msg, const DAQ_ModFlow_t *modify)
{
    DumpContext* dc = (DumpContext*) handle;

    if (dc->text_out)
    {
        const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;
        fprintf(dc->text_out, "MF: %lu.%lu(%u): %d %u \n", (unsigned long) hdr->ts.tv_sec,
                (unsigned long) hdr->ts.tv_usec, msg->data_len, modify->type, modify->length);
        hexdump(dc->text_out, modify->value, modify->length, "    ");
    }
    return DAQ_SUCCESS;
}

static int dump_daq_dp_add_dc(void *handle, const DAQ_Msg_t *msg, DAQ_DP_key_t *dp_key,
                                const uint8_t *packet_data, DAQ_Data_Channel_Params_t *params)
{
    DumpContext* dc = (DumpContext*) handle;

    if (dc->text_out)
    {
        const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;
        char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN];

        fprintf(dc->text_out, "DP: %lu.%lu(%u):\n", (unsigned long) hdr->ts.tv_sec,
                (unsigned long) hdr->ts.tv_usec, msg->data_len);
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
        DAQ_PktHdr_t *hdr = (DAQ_PktHdr_t *) msg->hdr;
        const uint8_t *data = msg->data;

        if (dc->dumper && s_fwd[verdict])
        {
            struct pcap_pkthdr pcap_hdr;

            pcap_hdr.ts = hdr->ts;
            pcap_hdr.caplen = msg->data_len;
            pcap_hdr.len = hdr->pktlen;
            pcap_dump((u_char *) dc->dumper, &pcap_hdr, data);
        }

        if (dc->text_out)
        {
            fprintf(dc->text_out, "PV: %lu.%lu(%u): %s\n", (unsigned long) hdr->ts.tv_sec,
                    (unsigned long) hdr->ts.tv_usec, msg->data_len, daq_verdict_strings[verdict]);
            if (verdict == DAQ_VERDICT_REPLACE)
                hexdump(dc->text_out, data, msg->data_len, "    ");
        }
    }

    return CALL_SUBAPI(dc, msg_finalize, msg, verdict);
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
    /* .set_filter = */ NULL,
    /* .start = */ dump_daq_start,
    /* .inject = */ dump_daq_inject,
    /* .breakloop = */ NULL,
    /* .stop = */ dump_daq_stop,
    /* .shutdown = */ dump_daq_shutdown,
    /* .get_stats = */ dump_daq_get_stats,
    /* .reset_stats = */ dump_daq_reset_stats,
    /* .get_snaplen = */ NULL,
    /* .get_capabilities = */ dump_daq_get_capabilities,
    /* .get_datalink_type = */ NULL,
    /* .get_device_index = */ NULL,
    /* .modify_flow = */ dump_daq_modify_flow,
    /* .query_flow = */ NULL,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .dp_add_dc = */ dump_daq_dp_add_dc,
    /* .msg_receive = */ NULL,
    /* .msg_finalize = */ dump_daq_msg_finalize,
    /* .get_msg_pool_info = */ NULL,
};


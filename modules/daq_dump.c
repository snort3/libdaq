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

#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "daq.h"
#include "daq_api.h"

#define DAQ_DUMP_VERSION 3

#define DAQ_DUMP_FILE "inline-out.pcap"

typedef struct
{
    // delegate most stuff to the wrapped module
    const DAQ_ModuleAPI_t *wrapped_module;
    void *wrapped_context;

    // but write all output packets here
    pcap_dumper_t *dump;
    char *output_filename;

    DAQ_Stats_t stats;
} DumpContext;

static DAQ_VariableDesc_t dump_variable_descriptions[] = {
    { "outfile", "PCAP filename to output transmitted packets to", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
};

DAQ_BaseAPI_t daq_base_api;


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
        snprintf(errBuf, errMax, "%s: No submodule configuration provided", __FUNCTION__);
        return DAQ_ERROR_INVAL;
    }

    dc = calloc(1, sizeof(DumpContext));
    if (!dc)
    {
        snprintf(errBuf, errMax, "%s: Couldn't allocate memory for the DAQ context", __FUNCTION__);
        return DAQ_ERROR_NOMEM;
    }

    daq_base_api.module_config_first_variable(config, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "outfile"))
        {
            dc->output_filename = strdup(varValue);
            if (!dc->output_filename)
            {
                snprintf(errBuf, errMax, "%s: Couldn't allocate memory for the output filename", __FUNCTION__);
                free(dc);
                return DAQ_ERROR_NOMEM;
            }
        }
        daq_base_api.module_config_next_variable(config, &varKey, &varValue);
    }

    dc->wrapped_module = daq_base_api.module_config_get_module(subconfig);
    rval = dc->wrapped_module->initialize(subconfig, &dc->wrapped_context, errBuf, errMax);
    if (rval != DAQ_SUCCESS)
    {
        if (dc->output_filename)
            free(dc->output_filename);
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
    if (dc->output_filename)
        free(dc->output_filename);
    free(dc);
}

static int dump_daq_inject (void *handle, const DAQ_PktHdr_t* hdr, const uint8_t* data, uint32_t len, int reverse)
{
    DumpContext *dc = (DumpContext*)handle;

    // copy the original header to get the same
    // timestamps but overwrite the lengths
    DAQ_PktHdr_t h = *hdr;

    h.pktlen = h.caplen = len;
    pcap_dump((u_char*)dc->dump, (struct pcap_pkthdr*)&h, data);

    if ( ferror(pcap_dump_file(dc->dump)) )
    {
        dc->wrapped_module->set_errbuf(dc->wrapped_context, "inject can't write to dump file");
        return DAQ_ERROR;
    }
    dc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------

static int dump_daq_start(void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    const char *name = dc->output_filename ? dc->output_filename : DAQ_DUMP_FILE;
    pcap_t *pcap;
    int dlt, snaplen, rval;

    rval = dc->wrapped_module->start(dc->wrapped_context);
    if (rval != DAQ_SUCCESS)
        return rval;

    dlt = dc->wrapped_module->get_datalink_type(dc->wrapped_context);
    snaplen = dc->wrapped_module->get_snaplen(dc->wrapped_context);

    pcap = pcap_open_dead(dlt, snaplen);

    dc->dump = pcap ? pcap_dump_open(pcap, name) : NULL;

    if (!dc->dump)
    {
        dc->wrapped_module->stop(dc->wrapped_context);
        dc->wrapped_module->set_errbuf(dc->wrapped_context, "can't open dump file");
        return DAQ_ERROR;
    }
    pcap_close(pcap);
    return DAQ_SUCCESS;
}

static int dump_daq_stop (void* handle)
{
    DumpContext *dc = (DumpContext*)handle;
    int err = dc->wrapped_module->stop(dc->wrapped_context);

    if ( err )
        return err;

    if ( dc->dump )
    {
        pcap_dump_close(dc->dump);
        dc->dump = NULL;
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

    for ( i = 0; i < MAX_DAQ_VERDICT; i++ )
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

static int dump_daq_msg_receive(void *handle, const DAQ_Msg_t **msgptr)
{
    DumpContext *dc = (DumpContext *) handle;

    return dc->wrapped_module->msg_receive(dc->wrapped_context, msgptr);
}

static const int s_fwd[MAX_DAQ_VERDICT] = { 1, 0, 1, 1, 0, 1, 0 };

static int dump_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    DumpContext *dc = (DumpContext *) handle;

    dc->stats.verdicts[verdict]++;
    if (msg->type == DAQ_MSG_TYPE_PACKET && s_fwd[verdict])
    {
        struct pcap_pkthdr pcap_hdr;
        DAQ_PktHdr_t *hdr = dc->wrapped_module->packet_header_from_msg(dc->wrapped_context, msg);
        const uint8_t *data = dc->wrapped_module->packet_data_from_msg(dc->wrapped_context, msg);

        pcap_hdr.ts = hdr->ts;
        pcap_hdr.caplen = hdr->caplen;
        pcap_hdr.len = hdr->pktlen;
        pcap_dump((u_char *) dc->dump, &pcap_hdr, data);
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
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ dump_daq_msg_receive,
    /* .msg_finalize = */ dump_daq_msg_finalize,
    /* .packet_header_from_msg = */ dump_daq_packet_header_from_msg,
    /* .packet_data_from_msg = */ dump_daq_packet_data_from_msg
};


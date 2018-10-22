/*
** Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <pcap.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "daq_module_api.h"

#define DAQ_DUMP_VERSION 5

#define DAQ_DUMP_PCAP_FILE "inline-out.pcap"

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

    pcap_dumper_t *dumper;
    char *filename;
    bool output;

    DAQ_Stats_t stats;
} DumpContext;

static DAQ_VariableDesc_t dump_variable_descriptions[] = {
    { "file", "PCAP filename to output transmitted packets to (default: " DAQ_DUMP_PCAP_FILE ")", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "output", "Set to none to prevent output from being written to file (deprecated)", DAQ_VAR_DESC_REQUIRES_ARGUMENT }
};

DAQ_BaseAPI_t daq_base_api;

//-------------------------------------------------------------------------

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

static int dump_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    DumpContext *dc;
    const char *varKey, *varValue;

    dc = calloc(1, sizeof(DumpContext));
    if (!dc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the DAQ context", __func__);
        return DAQ_ERROR_NOMEM;
    }
    dc->modinst = modinst;
    dc->output = true;

    if (daq_base_api.resolve_subapi(modinst, &dc->subapi) != DAQ_SUCCESS)
    {
        SET_ERROR(modinst, "%s: Couldn't resolve subapi. No submodule configured?", __func__);
        free(dc);
        return DAQ_ERROR_INVAL;
    }

    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "file"))
        {
            dc->filename = strdup(varValue);
            if (!dc->filename)
            {
                SET_ERROR(modinst, "%s: Couldn't allocate memory for the PCAP output filename", __func__);
                free(dc);
                return DAQ_ERROR_NOMEM;
            }
        }
        else if (!strcmp(varKey, "output"))
        {
            if (!strcmp(varValue, "none"))
                dc->output = false;
            else
            {
                SET_ERROR(modinst, "%s: Invalid output type (%s)", __func__, varValue);
                free(dc);
                return DAQ_ERROR_INVAL;
            }
        }
        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    *ctxt_ptr = dc;

    return DAQ_SUCCESS;
}

static void dump_daq_destroy(void *handle)
{
    DumpContext *dc = (DumpContext *) handle;

    if (dc->dumper)
        pcap_dump_close(dc->dumper);
    if (dc->filename)
        free(dc->filename);
    free(dc);
}

static int dump_daq_inject(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t len, int reverse)
{
    DumpContext *dc = (DumpContext*) handle;
    const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;

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

    if (CHECK_SUBAPI(dc, inject))
    {
        int rval = CALL_SUBAPI(dc, inject, msg, data, len, reverse);
        if (rval != DAQ_SUCCESS)
            return rval;
    }

    dc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int dump_daq_start(void *handle)
{
    DumpContext *dc = (DumpContext*) handle;

    int rval = CALL_SUBAPI_NOARGS(dc, start);
    if (rval != DAQ_SUCCESS)
        return rval;

    int dlt = CALL_SUBAPI_NOARGS(dc, get_datalink_type);
    int snaplen = CALL_SUBAPI_NOARGS(dc, get_snaplen);

    if (dc->output)
    {
        const char *filename = dc->filename ? dc->filename : DAQ_DUMP_PCAP_FILE;
        pcap_t *pcap;

        pcap = pcap_open_dead(dlt, snaplen);
        if (!pcap)
        {
            CALL_SUBAPI_NOARGS(dc, stop);
            SET_ERROR(dc->modinst, "Could not create a dead PCAP handle!");
            return DAQ_ERROR;
        }
        dc->dumper = pcap_dump_open(pcap, filename);
        if (!dc->dumper)
        {
            CALL_SUBAPI_NOARGS(dc, stop);
            SET_ERROR(dc->modinst, "Could not open PCAP %s for writing: %s", filename, pcap_geterr(pcap));
            pcap_close(pcap);
            return DAQ_ERROR;
        }
        pcap_close(pcap);
    }

    return DAQ_SUCCESS;
}

static int dump_daq_stop(void *handle)
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

    return DAQ_SUCCESS;
}

static int dump_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    DumpContext *dc = (DumpContext*) handle;
    int rval = DAQ_SUCCESS;

    if (CHECK_SUBAPI(dc, get_stats))
    {
        rval = CALL_SUBAPI(dc, get_stats, stats);
        /* Use our own concept of verdict and injected packet stats */
        for (int i = 0; i < MAX_DAQ_VERDICT; i++)
            stats->verdicts[i] = dc->stats.verdicts[i];
        stats->packets_injected = dc->stats.packets_injected;
    }
    else
        *stats = dc->stats;

    return rval;
}

static void dump_daq_reset_stats(void *handle)
{
    DumpContext *dc = (DumpContext*) handle;
    if (CHECK_SUBAPI(dc, reset_stats))
        CALL_SUBAPI_NOARGS(dc, reset_stats);
    memset(&dc->stats, 0, sizeof(dc->stats));
}

static uint32_t dump_daq_get_capabilities(void *handle)
{
    DumpContext *dc = (DumpContext*) handle;
    uint32_t caps = CHECK_SUBAPI(dc, get_capabilities) ? CALL_SUBAPI_NOARGS(dc, get_capabilities) : 0;
    caps |= DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT;
    return caps;
}

static int dump_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    DumpContext *dc = (DumpContext *) handle;

    dc->stats.verdicts[verdict]++;
    if (msg->type == DAQ_MSG_TYPE_PACKET)
    {
        DAQ_PktHdr_t *hdr = (DAQ_PktHdr_t *) msg->hdr;
        const uint8_t *data = msg->data;
        static const int s_fwd[MAX_DAQ_VERDICT] = { 1, 0, 1, 1, 0, 1, 0 };

        if (dc->dumper && s_fwd[verdict])
        {
            struct pcap_pkthdr pcap_hdr;

            pcap_hdr.ts = hdr->ts;
            pcap_hdr.caplen = msg->data_len;
            pcap_hdr.len = hdr->pktlen;
            pcap_dump((u_char *) dc->dumper, &pcap_hdr, data);
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
    /* .instantiate = */ dump_daq_instantiate,
    /* .destroy = */ dump_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ dump_daq_start,
    /* .inject = */ dump_daq_inject,
    /* .breakloop = */ NULL,
    /* .stop = */ dump_daq_stop,
    /* .ioctl = */ NULL,
    /* .get_stats = */ dump_daq_get_stats,
    /* .reset_stats = */ dump_daq_reset_stats,
    /* .get_snaplen = */ NULL,
    /* .get_capabilities = */ dump_daq_get_capabilities,
    /* .get_datalink_type = */ NULL,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ NULL,
    /* .msg_finalize = */ dump_daq_msg_finalize,
    /* .get_msg_pool_info = */ NULL,
};


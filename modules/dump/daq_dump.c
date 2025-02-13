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

#include <pcap.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "daq_module_api.h"

#define DAQ_DUMP_VERSION 5

#define DEFAULT_TX_DUMP_FILE "inline-out.pcap"
#define DEFAULT_RX_DUMP_FILE "inline-in.pcap"

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

    pcap_dumper_t *tx_dumper;
    char *tx_filename;

    pcap_dumper_t *rx_dumper;
    char *rx_filename;

    DAQ_Stats_t stats;
} DumpContext;

static DAQ_VariableDesc_t dump_variable_descriptions[] = {
    { "file", "PCAP filename to output transmitted packets to (default: " DEFAULT_TX_DUMP_FILE ")", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "output", "Set to none to prevent output from being written to file (deprecated)", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "dump-rx", "Also dump received packets to their own PCAP file (default: " DEFAULT_RX_DUMP_FILE ")", 0 }
};

static DAQ_BaseAPI_t daq_base_api;

//-------------------------------------------------------------------------

static int dump_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int dump_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int dump_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = dump_variable_descriptions;

    return sizeof(dump_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int dump_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    // Simple multi-instance sanity check
    unsigned total_instances = daq_base_api.config_get_total_instances(modcfg);
    unsigned instance_id = daq_base_api.config_get_instance_id(modcfg);
    if (total_instances > 1 && instance_id == 0)
    {
        SET_ERROR(modinst, "%s: Instance ID required for multi-instance (%u instances expected)", __func__, total_instances);
        return DAQ_ERROR_INVAL;
    }

    DumpContext *dc = calloc(1, sizeof(DumpContext));
    if (!dc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the DAQ context", __func__);
        return DAQ_ERROR_NOMEM;
    }
    dc->modinst = modinst;

    if (daq_base_api.resolve_subapi(modinst, &dc->subapi) != DAQ_SUCCESS)
    {
        SET_ERROR(modinst, "%s: Couldn't resolve subapi. No submodule configured?", __func__);
        free(dc);
        return DAQ_ERROR_INVAL;
    }

    const char *tx_filename = DEFAULT_TX_DUMP_FILE;
    const char *rx_filename = NULL;
    const char *varKey, *varValue;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "file"))
            tx_filename = varValue;
        else if (!strcmp(varKey, "dump-rx"))
            rx_filename = varValue ? varValue : DEFAULT_RX_DUMP_FILE;
        else if (!strcmp(varKey, "output"))
        {
            if (!strcmp(varValue, "none"))
                tx_filename = NULL;
            else
            {
                SET_ERROR(modinst, "%s: Invalid output type (%s)", __func__, varValue);
                free(dc);
                return DAQ_ERROR_INVAL;
            }
        }
        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    // Mangle the output filenames with a prefix in the multi-instance scenario
    char prefix[32];
    if (instance_id > 0)
    {
        // For now, only support mangling base filenames (no directory path allowed)
        if (tx_filename && strchr(tx_filename, '/'))
        {
            SET_ERROR(modinst, "%s: Invalid TX PCAP filename for multi-instance: %s", __func__, tx_filename);
            free(dc);
            return DAQ_ERROR_INVAL;
        }

        if (rx_filename && strchr(rx_filename, '/'))
        {
            SET_ERROR(modinst, "%s: Invalid RX PCAP filename for multi-instance: %s", __func__, rx_filename);
            free(dc);
            return DAQ_ERROR_INVAL;
        }

        snprintf(prefix, sizeof(prefix), "%u_", instance_id);
    }
    else
        prefix[0] = '\0';

    if (tx_filename)
    {
        size_t len = strlen(tx_filename) + strlen(prefix) + 1;
        dc->tx_filename = malloc(len);
        if (!dc->tx_filename)
        {
            SET_ERROR(modinst, "%s: Couldn't allocate memory for the TX PCAP filename", __func__);
            free(dc);
            return DAQ_ERROR_NOMEM;
        }
        snprintf(dc->tx_filename, len, "%s%s", prefix, tx_filename);
    }

    if (rx_filename)
    {
        size_t len = strlen(rx_filename) + strlen(prefix) + 1;
        dc->rx_filename = malloc(len);
        if (!dc->rx_filename)
        {
            SET_ERROR(modinst, "%s: Couldn't allocate memory for the RX PCAP filename", __func__);
            free(dc->tx_filename);
            free(dc);
            return DAQ_ERROR_NOMEM;
        }
        snprintf(dc->rx_filename, len, "%s%s", prefix, rx_filename);
    }

    *ctxt_ptr = dc;

    return DAQ_SUCCESS;
}

static void dump_daq_destroy(void *handle)
{
    DumpContext *dc = (DumpContext *) handle;

    if (dc->tx_dumper)
        pcap_dump_close(dc->tx_dumper);
    free(dc->tx_filename);
    if (dc->rx_dumper)
        pcap_dump_close(dc->rx_dumper);
    free(dc->rx_filename);
    free(dc);
}

static int dump_daq_start(void *handle)
{
    DumpContext *dc = (DumpContext*) handle;

    int rval = CALL_SUBAPI_NOARGS(dc, start);
    if (rval != DAQ_SUCCESS)
        return rval;

    int dlt = CALL_SUBAPI_NOARGS(dc, get_datalink_type);
    int snaplen = CALL_SUBAPI_NOARGS(dc, get_snaplen);

    if (dc->tx_filename)
    {
        pcap_t *pcap = pcap_open_dead(dlt, snaplen);
        if (!pcap)
        {
            CALL_SUBAPI_NOARGS(dc, stop);
            SET_ERROR(dc->modinst, "Could not create a dead PCAP handle!");
            return DAQ_ERROR;
        }
        dc->tx_dumper = pcap_dump_open(pcap, dc->tx_filename);
        if (!dc->tx_dumper)
        {
            CALL_SUBAPI_NOARGS(dc, stop);
            SET_ERROR(dc->modinst, "Could not open PCAP %s for writing: %s", dc->tx_filename, pcap_geterr(pcap));
            pcap_close(pcap);
            return DAQ_ERROR;
        }
        pcap_close(pcap);
    }

    if (dc->rx_filename)
    {
        pcap_t *pcap = pcap_open_dead(dlt, snaplen);
        if (!pcap)
        {
            CALL_SUBAPI_NOARGS(dc, stop);
            SET_ERROR(dc->modinst, "Could not create a dead PCAP handle!");
            return DAQ_ERROR;
        }
        dc->rx_dumper = pcap_dump_open(pcap, dc->rx_filename);
        if (!dc->rx_dumper)
        {
            CALL_SUBAPI_NOARGS(dc, stop);
            SET_ERROR(dc->modinst, "Could not open PCAP %s for writing: %s", dc->rx_filename, pcap_geterr(pcap));
            pcap_close(pcap);
            return DAQ_ERROR;
        }
        pcap_close(pcap);
    }

    return DAQ_SUCCESS;
}

static int dump_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    DumpContext *dc = (DumpContext*) handle;

    if (dc->tx_dumper && type == DAQ_MSG_TYPE_PACKET)
    {
        const DAQ_PktHdr_t *pkthdr = (const DAQ_PktHdr_t *) hdr;
        struct pcap_pkthdr pcap_hdr;

        pcap_hdr.ts.tv_sec = pkthdr->ts.tv_sec;
        pcap_hdr.ts.tv_usec = pkthdr->ts.tv_usec;
        pcap_hdr.caplen = data_len;
        pcap_hdr.len = data_len;

        pcap_dump((u_char *) dc->tx_dumper, &pcap_hdr, data);
    }

    if (CHECK_SUBAPI(dc, inject))
    {
        int rval = CALL_SUBAPI(dc, inject, type, hdr, data, data_len);
        if (rval != DAQ_SUCCESS)
            return rval;
    }

    dc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int dump_daq_inject_relative(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    DumpContext *dc = (DumpContext*) handle;

    if (dc->tx_dumper && msg->type == DAQ_MSG_TYPE_PACKET)
    {
        const DAQ_PktHdr_t *pkthdr = (const DAQ_PktHdr_t *) msg->hdr;
        struct pcap_pkthdr pcap_hdr;

        // Reuse the timestamp from the original packet for the injected packet
        pcap_hdr.ts.tv_sec = pkthdr->ts.tv_sec;
        pcap_hdr.ts.tv_usec = pkthdr->ts.tv_usec;
        pcap_hdr.caplen = data_len;
        pcap_hdr.len = data_len;

        pcap_dump((u_char *) dc->tx_dumper, &pcap_hdr, data);
    }

    if (CHECK_SUBAPI(dc, inject_relative))
    {
        int rval = CALL_SUBAPI(dc, inject_relative, msg, data, data_len, reverse);
        if (rval != DAQ_SUCCESS)
            return rval;
    }

    dc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static int dump_daq_stop(void *handle)
{
    DumpContext *dc = (DumpContext*) handle;
    int rval = CALL_SUBAPI_NOARGS(dc, stop);

    if (rval != DAQ_SUCCESS)
        return rval;

    if (dc->tx_dumper)
    {
        pcap_dump_close(dc->tx_dumper);
        dc->tx_dumper = NULL;
    }

    if (dc->rx_dumper)
    {
        pcap_dump_close(dc->rx_dumper);
        dc->rx_dumper = NULL;
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

static unsigned dump_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    DumpContext *dc = (DumpContext*) handle;
    unsigned num_receive = CALL_SUBAPI(dc, msg_receive, max_recv, msgs, rstat);

    if (dc->rx_dumper)
    {
        for (unsigned idx = 0; idx < num_receive; idx++)
        {
            const DAQ_Msg_t *msg = msgs[idx];

            if (msg->type != DAQ_MSG_TYPE_PACKET)
                continue;

            const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;
            const uint8_t *data = msg->data;
            struct pcap_pkthdr pcap_hdr;

            pcap_hdr.ts.tv_sec = hdr->ts.tv_sec;
            pcap_hdr.ts.tv_usec = hdr->ts.tv_usec;
            pcap_hdr.caplen = msg->data_len;
            pcap_hdr.len = hdr->pktlen;
            pcap_dump((u_char *) dc->rx_dumper, &pcap_hdr, data);
        }
    }

    return num_receive;
}

static int dump_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    static const int s_fwd[MAX_DAQ_VERDICT] = { 1, 0, 1, 1, 0, 1 };
    DumpContext *dc = (DumpContext *) handle;

    dc->stats.verdicts[verdict]++;
    if (dc->tx_dumper && msg->type == DAQ_MSG_TYPE_PACKET && s_fwd[verdict])
    {
        const DAQ_PktHdr_t *hdr = (const DAQ_PktHdr_t *) msg->hdr;
        const uint8_t *data = msg->data;
        struct pcap_pkthdr pcap_hdr;

        pcap_hdr.ts.tv_sec = hdr->ts.tv_sec;
        pcap_hdr.ts.tv_usec = hdr->ts.tv_usec;
        pcap_hdr.caplen = msg->data_len;
        pcap_hdr.len = hdr->pktlen;
        pcap_dump((u_char *) dc->tx_dumper, &pcap_hdr, data);
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
    /* .load = */ dump_daq_module_load,
    /* .unload = */ dump_daq_module_unload,
    /* .get_variable_descs = */ dump_daq_get_variable_descs,
    /* .instantiate = */ dump_daq_instantiate,
    /* .destroy = */ dump_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ dump_daq_start,
    /* .inject = */ dump_daq_inject,
    /* .inject_relative = */ dump_daq_inject_relative,
    /* .interrupt = */ NULL,
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
    /* .msg_receive = */ dump_daq_msg_receive,
    /* .msg_finalize = */ dump_daq_msg_finalize,
    /* .get_msg_pool_info = */ NULL,
};


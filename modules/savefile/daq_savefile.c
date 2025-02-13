/*
** Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "daq_dlt.h"
#include "daq_module_api.h"

#define DAQ_SAVEFILE_VERSION 1

#define SAVEFILE_DEFAULT_POOL_SIZE 16
#define SAVEFILE_BUF_SZ 16384

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

/* Standard libpcap format. */
#define TCPDUMP_MAGIC       0xa1b2c3d4

/* Normal libpcap format, except for seconds/nanoseconds timestamps */
#define NSEC_TCPDUMP_MAGIC  0xa1b23c4d

/* PCAP savefile file format version */
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

struct pcap_file_header
{
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;       /* gmt to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length saved portion of each pkt */
    uint32_t linktype;      /* data link type (LINKTYPE_*) */
};

struct pcap_timeval {
    int32_t tv_sec;       /* seconds */
    int32_t tv_usec;      /* microseconds */
};

struct pcap_sf_pkthdr
{
    struct pcap_timeval ts; /* time stamp */
    uint32_t caplen;        /* length of portion present */
    uint32_t len;           /* length this packet (off wire) */
};

typedef struct _savefile_msg_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    struct _savefile_msg_desc *next;
} SavefileMsgDesc;

typedef struct
{
    SavefileMsgDesc *pool;
    SavefileMsgDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} SavefileMsgPool;

typedef struct
{
    /* Configuration */
    char *filename;
    unsigned snaplen;
    /* State */
    DAQ_ModuleInstance_h modinst;
    DAQ_Stats_t stats;
    SavefileMsgPool pool;
    struct pcap_file_header *pfhdr;
    uint8_t *file_data;
    off_t file_size;
    off_t file_offset;
    int fd;
    volatile bool interrupted;
} SavefileContext;

static DAQ_BaseAPI_t daq_base_api;

static void destroy_message_pool(SavefileContext *sfc)
{
    SavefileMsgPool *pool = &sfc->pool;
    if (pool->pool)
    {
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

static int create_message_pool(SavefileContext *sfc, unsigned size)
{
    SavefileMsgPool *pool = &sfc->pool;
    pool->pool = calloc(sizeof(SavefileMsgDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(sfc->modinst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(SavefileMsgDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(SavefileMsgDesc) * size;
    while (pool->info.size < size)
    {
        /* Set up descriptor */
        SavefileMsgDesc *desc = &pool->pool[pool->info.size];

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(desc->pkthdr);
        msg->hdr = &desc->pkthdr;
        msg->owner = sfc->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

static DAQ_RecvStatus savefile_read_message(SavefileContext *sfc, SavefileMsgDesc *desc)
{
    /* First, try to read the record header. */
    struct pcap_sf_pkthdr *sfhdr;
    if (sfc->file_offset + sizeof(*sfhdr) > sfc->file_size)
    {
        SET_ERROR(sfc->modinst, "%s: Truncated PCAP packet header!", __func__);
        return DAQ_RSTAT_ERROR;
    }
    sfhdr = (struct pcap_sf_pkthdr *) (sfc->file_data + sfc->file_offset);
    sfc->file_offset += sizeof(*sfhdr);

    if (sfhdr->caplen > sfc->pfhdr->snaplen)
    {
        SET_ERROR(sfc->modinst, "%s: Savefile header has invalid caplen: %u (> %u)", __func__,
                sfhdr->caplen, sfc->pfhdr->snaplen);
        return DAQ_RSTAT_ERROR;
    }

    if (sfhdr->caplen > sfc->snaplen)
    {
        SET_ERROR(sfc->modinst, "%s: Savefile header has invalid caplen: %u", __func__, sfhdr->caplen);
        return DAQ_RSTAT_ERROR;
    }

    if (sfc->file_offset + sfhdr->caplen > sfc->file_size)
    {
        SET_ERROR(sfc->modinst, "%s: Truncated PCAP packet data!", __func__);
        return DAQ_RSTAT_ERROR;
    }

    /* Set up the DAQ message.  Most fields are prepopulated and unchanging. */
    DAQ_Msg_t *msg = &desc->msg;
    msg->data = sfc->file_data + sfc->file_offset;
    msg->data_len = sfhdr->caplen;
    sfc->file_offset += sfhdr->caplen;

    /* Then, set up the DAQ packet header. */
    DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
    pkthdr->pktlen = sfhdr->len;
    pkthdr->ts.tv_sec = sfhdr->ts.tv_sec;
    pkthdr->ts.tv_usec = sfhdr->ts.tv_usec;

    return DAQ_RSTAT_OK;
}

static int savefile_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int savefile_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int savefile_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void** ctxt_ptr)
{
    SavefileContext *sfc;
    int rval = DAQ_ERROR;

    sfc = calloc(1, sizeof(SavefileContext));
    if (!sfc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new Savefile context!", __func__);
        return DAQ_ERROR_NOMEM;
    }
    sfc->modinst = modinst;

    sfc->fd = -1;
    sfc->file_data = MAP_FAILED;

    sfc->snaplen = daq_base_api.config_get_snaplen(modcfg);

    const char *filename = daq_base_api.config_get_input(modcfg);
    if (!filename)
    {
        SET_ERROR(modinst, "%s: No filename given!", __func__);
        goto err;
    }

    sfc->filename = strdup(filename);
    if (!sfc)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the filename!", __func__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    rval = create_message_pool(sfc, pool_size ? pool_size : SAVEFILE_DEFAULT_POOL_SIZE);
    if (rval != DAQ_SUCCESS)
        goto err;

    *ctxt_ptr = sfc;

    return DAQ_SUCCESS;

err:
    if (sfc->filename)
        free(sfc->filename);
    destroy_message_pool(sfc);
    free(sfc);
    return rval;
}

static void savefile_daq_destroy(void *handle)
{
    SavefileContext *sfc = (SavefileContext *) handle;

    if (sfc->filename)
        free(sfc->filename);
    destroy_message_pool(sfc);
    free(sfc);
}

static int savefile_daq_start(void *handle)
{
    SavefileContext *sfc = (SavefileContext *) handle;

    sfc->fd = open(sfc->filename, O_RDONLY);
    if (sfc->fd == -1)
    {
        SET_ERROR(sfc->modinst, "%s: Couldn't open %s: %s (%d)", __func__, sfc->filename,
                strerror(errno), errno);
        return DAQ_ERROR;
    }

    struct stat sb;
    if (fstat(sfc->fd, &sb) == -1)
    {
        SET_ERROR(sfc->modinst, "%s: Couldn't stat %s: %s (%d)", __func__, sfc->filename,
                strerror(errno), errno);
        goto err;
    }
    sfc->file_size = sb.st_size;

    sfc->file_data = mmap(NULL, sfc->file_size, PROT_READ, MAP_PRIVATE, sfc->fd, 0);
    if (sfc->file_data == MAP_FAILED)
    {
        SET_ERROR(sfc->modinst, "%s: Couldn't mmap %zu bytes of %s: %s (%d)", __func__, sfc->file_size,
                sfc->filename, strerror(errno), errno);
        goto err;
    }

    /* Validate the PCAP file header. */
    if (sfc->file_size < sizeof(struct pcap_file_header))
    {
        SET_ERROR(sfc->modinst, "%s: Truncated PCAP file header!", __func__);
        goto err;
    }
    struct pcap_file_header *pfhdr = (struct pcap_file_header *) sfc->file_data;

    /* Check the first 4 bytes for the PCAP savefile magic numbers. */
    if (pfhdr->magic != TCPDUMP_MAGIC && pfhdr->magic != NSEC_TCPDUMP_MAGIC)
    {
        SET_ERROR(sfc->modinst, "%s: Invalid PCAP savefile magic: %x", __func__, pfhdr->magic);
        goto err;
    }

    /* Validate the file format version (only 2.4 is supported). */
    if (pfhdr->version_major != PCAP_VERSION_MAJOR || pfhdr->version_minor != PCAP_VERSION_MINOR)
    {
        SET_ERROR(sfc->modinst, "%s: Invalid PCAP savefile version: %u.%u", __func__,
                pfhdr->version_major, pfhdr->version_minor);
        goto err;
    }

    /* Sanity-check the linktype.  We only support a select few that don't need translation
        so that we don't need to support a mapping like libpcap does. */
    int dlt = (pfhdr->linktype & 0x03FFFFFF);
    if (dlt != DLT_EN10MB)
    {
        SET_ERROR(sfc->modinst, "%s: Unsupported PCAP savefile linktype: %u", __func__, pfhdr->linktype);
        goto err;
    }

    sfc->pfhdr = pfhdr;
    sfc->file_offset = sizeof(*pfhdr);

    return DAQ_SUCCESS;

err:
    if (sfc->file_data != MAP_FAILED)
        munmap(sfc->file_data, sfc->file_size);
    if (sfc->fd != -1)
    {
        close(sfc->fd);
        sfc->fd = -1;
    }
    return DAQ_ERROR;
}

static int savefile_daq_interrupt(void *handle)
{
    SavefileContext *sfc = (SavefileContext *) handle;

    sfc->interrupted = true;

    return DAQ_SUCCESS;
}

static int savefile_daq_stop (void *handle)
{
    SavefileContext *sfc = (SavefileContext *) handle;

    if (sfc->file_data != MAP_FAILED)
        munmap(sfc->file_data, sfc->file_size);
    if (sfc->fd != -1)
    {
        close(sfc->fd);
        sfc->fd = -1;
    }

    return DAQ_SUCCESS;
}

static int savefile_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    SavefileContext *sfc = (SavefileContext *) handle;

    memcpy(stats, &sfc->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void savefile_daq_reset_stats(void *handle)
{
    SavefileContext *sfc = (SavefileContext *) handle;
    memset(&sfc->stats, 0, sizeof(sfc->stats));
}

static int savefile_daq_get_snaplen (void *handle)
{
    SavefileContext *sfc = (SavefileContext *) handle;
    return sfc->snaplen;
}

static uint32_t savefile_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_INTERRUPT | DAQ_CAPA_UNPRIV_START;
}

static int savefile_daq_get_datalink_type(void *handle)
{
    SavefileContext *sfc = (SavefileContext *) handle;
    return (sfc->pfhdr->linktype & 0x03FFFFFF);
}

static unsigned savefile_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    SavefileContext *sfc = (SavefileContext *) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    unsigned idx = 0;

    while (idx < max_recv && status == DAQ_RSTAT_OK)
    {
        /* Check to see if the receive has been canceled.  If so, reset it and return appropriately. */
        if (sfc->interrupted)
        {
            sfc->interrupted = false;
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        if (sfc->file_offset == sfc->file_size)
        {
            status = DAQ_RSTAT_EOF;
            break;
        }

        /* Make sure that we have a message descriptor available to populate. */
        SavefileMsgDesc *desc = sfc->pool.freelist;
        if (!desc)
        {
            status = DAQ_RSTAT_NOBUF;
            break;
        }

        /* Attempt to read a message into the descriptor. */
        status = savefile_read_message(sfc, desc);
        if (status != DAQ_RSTAT_OK)
            break;
        sfc->stats.packets_received++;

        /* Last, but not least, extract this descriptor from the free list and
           place the message in the return vector. */
        sfc->pool.freelist = desc->next;
        desc->next = NULL;
        sfc->pool.info.available--;
        msgs[idx] = &desc->msg;

        idx++;
    }

    *rstat = status;

    return idx;
}

static int savefile_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    SavefileContext *sfc = (SavefileContext *) handle;
    SavefileMsgDesc *desc = (SavefileMsgDesc *) msg->priv;

    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    sfc->stats.verdicts[verdict]++;

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = sfc->pool.freelist;
    sfc->pool.freelist = desc;
    sfc->pool.info.available++;

    return DAQ_SUCCESS;
}

static int savefile_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    SavefileContext *sfc = (SavefileContext *) handle;

    *info = sfc->pool.info;

    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t savefile_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_SAVEFILE_VERSION,
    /* .name = */ "savefile",
    /* .type = */ DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ savefile_daq_module_load,
    /* .unload = */ savefile_daq_module_unload,
    /* .get_variable_descs = */ NULL,
    /* .instantiate = */ savefile_daq_instantiate,
    /* .destroy = */ savefile_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ savefile_daq_start,
    /* .inject = */ NULL,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ savefile_daq_interrupt,
    /* .stop = */ savefile_daq_stop,
    /* .ioctl = */ NULL,
    /* .get_stats = */ savefile_daq_get_stats,
    /* .reset_stats = */ savefile_daq_reset_stats,
    /* .get_snaplen = */ savefile_daq_get_snaplen,
    /* .get_capabilities = */ savefile_daq_get_capabilities,
    /* .get_datalink_type = */ savefile_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ savefile_daq_msg_receive,
    /* .msg_finalize = */ savefile_daq_msg_finalize,
    /* .get_msg_pool_info = */ savefile_daq_get_msg_pool_info,
};


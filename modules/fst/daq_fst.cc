/*
** Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <cassert>
#include <cstring>
#include <queue>
#include <vector>

#include "daq_dlt.h"
#include "daq_module_api.h"
#include "fst.h"

//#define DEBUG_DAQ_FST
#ifdef DEBUG_DAQ_FST
#include <cstdio>
#define debugf(...) printf(__VA_ARGS__)
#else
#define debugf(...)
#endif

#define DAQ_FST_VERSION 1

#define DEFAULT_FST_SIZE  1024

#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

#define CHECK_SUBAPI(ctxt, fname) \
    (ctxt->subapi.fname.func != NULL)

#define CALL_SUBAPI_NOARGS(ctxt, fname) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context)

#define CALL_SUBAPI(ctxt, fname, ...) \
    ctxt->subapi.fname.func(ctxt->subapi.fname.context, __VA_ARGS__)

struct FstMsgDesc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    DAQ_PktDecodeData_t decoded;
    DAQ_PktTcpAckData_t tcp_meta_ack;
    uint32_t acks_to_finalize;
    std::shared_ptr<FstEntry> entry;
    const DAQ_Msg_t *wrapped_msg;
};

struct FstMsgPool
{
    bool exhausted() { return freelist.empty(); }
    FstMsgDesc *get_free();
    void put_free(FstMsgDesc *desc);

    FstMsgDesc *pool;
    std::vector<FstMsgDesc*> freelist;
    DAQ_MsgPoolInfo_t info;
};

struct FstContext
{
    /* Configuration */
    bool binding_verdicts = true;
    bool meta_ack_enabled = false;
    bool ignore_checksums = false;
    /* State */
    DAQ_ModuleInstance_h modinst;
    DAQ_InstanceAPI_t subapi;
    FstMsgPool pool = { };
    DAQ_RecvStatus last_rstat;
    uint32_t last_flow_id;
    int dlt;
    FlowStateTable flow_table;
    std::deque<DAQ_Msg_h> limbo;
    std::queue<DAQ_Msg_h> held_bare_acks;
    uint32_t acks_to_finalize = 0;
    uint64_t processed = 0;
};


static DAQ_VariableDesc_t fst_variable_descriptions[] = {
    { "no_binding_verdicts", "Disables enforcement of binding verdicts", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "enable_meta_ack", "Enables support for filtering bare TCP acks", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "ignore_checksums", "Ignore bad checksums while decoding", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

static DAQ_BaseAPI_t daq_base_api;


/* --------------------------------------------------------------------------------------------- */

FstMsgDesc *FstMsgPool::get_free()
{
    if (freelist.empty())
        return nullptr;
    FstMsgDesc *desc = freelist.back();
    freelist.pop_back();
    info.available--;
    return desc;
}

void FstMsgPool::put_free(FstMsgDesc *desc)
{
    freelist.push_back(desc);
    info.available++;
}

static bool decode_packet(FstContext *fc, const uint8_t *packet_data, uint32_t packet_data_len, DecodeData *dd)
{
    decode_data_init(dd, packet_data, fc->ignore_checksums);
    switch (fc->dlt)
    {
        case DLT_EN10MB:
            return decode_eth(packet_data, packet_data_len, dd);
        case DLT_RAW:
            return decode_raw(packet_data, packet_data_len, dd);
        case DLT_IPV4:
            return decode_ip(packet_data, packet_data_len, dd);
        case DLT_IPV6:
            return decode_ip6(packet_data, packet_data_len, dd);
    }
    return false;
}


/*
 * DAQ Module API Implementation
 */

static int fst_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int fst_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int fst_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = fst_variable_descriptions;

    return sizeof(fst_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int fst_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    FstContext *fc;

    fc = new FstContext();
    fc->modinst = modinst;

    if (daq_base_api.resolve_subapi(modinst, &fc->subapi) != DAQ_SUCCESS)
    {
        SET_ERROR(modinst, "%s: Couldn't resolve subapi. No submodule configured?", __func__);
        delete fc;
        return DAQ_ERROR_INVAL;
    }

    const char *varKey, *varValue;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if (!strcmp(varKey, "no_binding_verdicts"))
            fc->binding_verdicts = false;
        else if (!strcmp(varKey, "enable_meta_ack"))
            fc->meta_ack_enabled = true;
        else if (!strcmp(varKey, "ignore_checksums"))
            fc->ignore_checksums = true;

        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    DAQ_MsgPoolInfo_t mpool_info;
    CALL_SUBAPI(fc, get_msg_pool_info, &mpool_info);
    uint32_t pool_size = mpool_info.size;
    fc->pool.pool = new FstMsgDesc[pool_size]();
    fc->pool.info.size = pool_size;
    fc->pool.info.mem_size = sizeof(FstMsgDesc) * pool_size;
    for (uint32_t i = 0; i < pool_size; i++)
    {
        FstMsgDesc* desc = &fc->pool.pool[i];
        DAQ_Msg_t* msg = &desc->msg;
        msg->owner = modinst;
        msg->priv = desc;
        fc->pool.put_free(desc);
    }

    fc->flow_table.set_max_size(DEFAULT_FST_SIZE);

    *ctxt_ptr = fc;

    return DAQ_SUCCESS;
}

static void fst_daq_destroy(void *handle)
{
    FstContext *fc = static_cast<FstContext*>(handle);

    fc->flow_table.clear();
    delete[] fc->pool.pool;
    delete fc;
}

static int fst_daq_start(void *handle)
{
    FstContext *fc = static_cast<FstContext*>(handle);

    int rval = CALL_SUBAPI_NOARGS(fc, start);
    if (rval != DAQ_SUCCESS)
        return rval;

    fc->dlt = CALL_SUBAPI_NOARGS(fc, get_datalink_type);

    return DAQ_SUCCESS;
}

static int fst_daq_stop(void *handle)
{
    FstContext *fc = static_cast<FstContext*>(handle);

    assert(fc->held_bare_acks.size() == fc->acks_to_finalize);
    while (!fc->held_bare_acks.empty())
    {
        DAQ_Msg_h bam = fc->held_bare_acks.front();
        fc->held_bare_acks.pop();
        debugf("Finalizing orphaned bare ACK (%u to go)\n", fc->acks_to_finalize);
        CALL_SUBAPI(fc, msg_finalize, bam, DAQ_VERDICT_PASS);
        fc->acks_to_finalize--;
    }

    return CALL_SUBAPI_NOARGS(fc, stop);
}

static bool process_lost_souls(FstContext *fc, const DAQ_Msg_t *msgs[], unsigned max_recv, unsigned &idx)
{
    if (fc->flow_table.purgatory_empty())
        return true;

    while (idx < max_recv && !fc->flow_table.purgatory_empty())
    {
        FstMsgDesc *desc = fc->pool.get_free();
        if (!desc)
            return false;

        std::shared_ptr<FstEntry> entry = fc->flow_table.get_lost_soul();
        /* Populate the message descriptor */
        desc->entry = entry;
        desc->wrapped_msg = nullptr;
        desc->acks_to_finalize = 0;
        /* Next, set up the DAQ EoF message. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_EOF;
        msg->hdr_len = sizeof(entry->flow_stats);
        msg->hdr = &entry->flow_stats;
        msg->data_len = 0;
        msg->data = nullptr;
        memset(msg->meta, 0, sizeof(msg->meta));
        msgs[idx++] = &desc->msg;

        debugf("%" PRIu64 ": Produced EoF message for flow %u\n", fc->processed, entry->flow_id);
    }

    /* Corner case: If EoF filled the last slot available (or there were none available to begin with),
        return false to indicate that processing was incomplete. */
    return idx < max_recv;
}

static bool process_new_soul(FstContext *fc, std::shared_ptr<FstEntry> entry, const DAQ_Msg_t *msgs[], unsigned max_recv, unsigned &idx)
{
    /* Populate the message descriptor */
    FstMsgDesc *desc = fc->pool.get_free();
    desc->entry = entry;
    desc->wrapped_msg = nullptr;
    desc->acks_to_finalize = 0;
    /* Next, set up the DAQ SoF message. */
    DAQ_Msg_t *msg = &desc->msg;
    msg->type = DAQ_MSG_TYPE_SOF;
    msg->hdr_len = sizeof(entry->flow_stats);
    msg->hdr = &entry->flow_stats;
    msg->data_len = 0;
    msg->data = nullptr;
    memset(msg->meta, 0, sizeof(msg->meta));
    msgs[idx++] = &desc->msg;

    debugf("%" PRIu64 ": Produced SoF message for flow %u\n", fc->processed, entry->flow_id);

    return true;
}

static bool process_daq_msg(FstContext *fc, const DAQ_Msg_t *orig_msg, const DAQ_Msg_t *msgs[], unsigned max_recv, unsigned &idx)
{
    fc->processed++;

    if (orig_msg->type != DAQ_MSG_TYPE_PACKET)
    {
        msgs[idx++] = orig_msg;
        return true;
    }

    const DAQ_PktHdr_t *orig_pkthdr = static_cast<const DAQ_PktHdr_t*>(orig_msg->hdr);
    fc->flow_table.process_timeouts(&orig_pkthdr->ts);

    if (!process_lost_souls(fc, msgs, max_recv, idx))
        return false;

    DecodeData dd;
    if (!decode_packet(fc, orig_msg->data, orig_msg->data_len, &dd) || (!dd.ip && !dd.ip6))
    {
        /* If we can't decode it or it's non-IP, we're not going to bother trying to classify it. */
        msgs[idx++] = orig_msg;
        return true;
    }

    if (fc->pool.exhausted())
        return false;

    FstKey key;
    memset(&key, 0, sizeof(key));
    bool swapped = key.populate(orig_pkthdr, &dd);

    FstNode *node = fc->flow_table.find(key);
    std::shared_ptr<FstEntry> entry;
    if (!node)
    {
        entry = std::make_shared<FstEntry>(orig_pkthdr, key, ++fc->last_flow_id, swapped);
        node = fc->flow_table.insert(key, entry);
        FstTimeoutList::ID tol_id;
        switch (key.protocol)
        {
            case IPPROTO_TCP:
                tol_id = FstTimeoutList::ID::TCP_SHORT;
                break;
            case IPPROTO_UDP:
                tol_id = FstTimeoutList::ID::UDP;
                break;
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                tol_id = FstTimeoutList::ID::ICMP;
                break;
            default:
                tol_id = FstTimeoutList::ID::OTHER;
                break;
        }
        fc->flow_table.move_node_to_timeout_list(node, tol_id);
        debugf("%" PRIu64 ": Created new flow %u\n", fc->processed, entry->flow_id);

        if (!process_new_soul(fc, entry, msgs, max_recv, idx))
            return false;
        /* Corner case: SoF filled the last slot available, return that processing was incomplete. */
        if (idx == max_recv)
            return false;
        /* Make sure there's still a free descriptor for the actual packet message */
        if (fc->pool.exhausted())
            return false;

        /* Don't update the entry stats until we're sure we'll be handling this packet message or
            it will be double counted. */
        entry->update_stats(orig_pkthdr, swapped);
    }
    else
    {
        entry = node->entry;
        debugf("%" PRIu64 ": Found existing flow %u (0x%x)\n", fc->processed, entry->flow_id, entry->flags);
        entry->update_stats(orig_pkthdr, swapped);
        if (entry->flags & (FST_ENTRY_FLAG_WHITELISTED | FST_ENTRY_FLAG_BLACKLISTED))
        {
            DAQ_Verdict verdict;
            if (entry->flags & FST_ENTRY_FLAG_WHITELISTED)
                verdict = DAQ_VERDICT_WHITELIST;
            else
                verdict = DAQ_VERDICT_BLACKLIST;
            debugf("%" PRIu64 ": %s message for flow %u\n", fc->processed, (verdict == DAQ_VERDICT_WHITELIST) ?
                    "Whitelisted" : "Blacklisted", entry->flow_id);
            /* FIXIT-L Check return code for finalizing messages and return some sort of error if it fails */
            CALL_SUBAPI(fc, msg_finalize, orig_msg, verdict);
            return true;
        }
    }

    bool c2s = (!swapped == !(entry->flags & FST_ENTRY_FLAG_SWAPPED));

    if (key.protocol == IPPROTO_TCP)
    {
        FstTcpTracker &tcp_tracker = entry->tcp_tracker;
        tcp_tracker.eval(dd, c2s);

        if (fc->meta_ack_enabled && tcp_tracker.process_bare_ack(dd, c2s))
        {
            debugf("%" PRIu64 ": Consuming bare ACK on flow %u\n", fc->processed, entry->flow_id);
            fc->held_bare_acks.push(orig_msg);
            ++fc->acks_to_finalize;
            return true;
        }
    }

    /* Populate the message descriptor */
    FstMsgDesc *desc = fc->pool.get_free();
    desc->entry = entry;
    desc->wrapped_msg = orig_msg;

    /* Next, set up the DAQ packet message. */
    DAQ_Msg_t *msg = &desc->msg;
    msg->type = DAQ_MSG_TYPE_PACKET;
    msg->hdr_len = sizeof(desc->pkthdr);
    msg->hdr = &desc->pkthdr;
    msg->data_len = orig_msg->data_len;
    msg->data = orig_msg->data;

    /* Copy over any metadata from the wrapped message that we won't produce. */
    for (int slot = 0; slot < DAQ_MSG_META_SLOTS; slot++)
    {
        if ((slot == DAQ_PKT_META_DECODE_DATA) || (slot == DAQ_PKT_META_TCP_ACK_DATA))
            continue;
        msg->meta[slot] = orig_msg->meta[slot];
    }

    /* Then, set up the DAQ packet header. */
    DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
    memcpy(pkthdr, orig_pkthdr, sizeof(desc->pkthdr));
    if (entry->flags & FST_ENTRY_FLAG_OPAQUE_SET)
    {
        pkthdr->opaque = entry->flow_stats.opaque;
        pkthdr->flags |= DAQ_PKT_FLAG_OPAQUE_IS_VALID;
    }
    pkthdr->flow_id = entry->flow_id;
    pkthdr->flags |= DAQ_PKT_FLAG_FLOWID_IS_VALID;
    if (entry->ha_state)
        pkthdr->flags |= DAQ_PKT_FLAG_HA_STATE_AVAIL;
    if (entry->flags & FST_ENTRY_FLAG_NEW)
    {
        pkthdr->flags |= DAQ_PKT_FLAG_NEW_FLOW;
        entry->flags &= ~FST_ENTRY_FLAG_NEW;
    }
    if (!c2s)
        pkthdr->flags |= DAQ_PKT_FLAG_REV_FLOW;

    /* Finally, set up the decode data slot. */
    desc->decoded = dd.decoded_data;
    msg->meta[DAQ_PKT_META_DECODE_DATA] = &desc->decoded;
    /* And (maybe) the TCP meta ACK slot. */
    msg->meta[DAQ_PKT_META_TCP_ACK_DATA] = nullptr;
    if (fc->meta_ack_enabled)
    {
        if (key.protocol == IPPROTO_TCP && dd.tcp_data_segment &&
                entry->tcp_tracker.get_meta_ack_data(desc->tcp_meta_ack, c2s))
        {
            msg->meta[DAQ_PKT_META_TCP_ACK_DATA] = &desc->tcp_meta_ack;
        }
        if (fc->acks_to_finalize)
        {
            desc->acks_to_finalize = fc->acks_to_finalize;
            fc->acks_to_finalize = 0;
            debugf("%" PRIu64 ": Scheduled %u bare ACKs to be finalized\n", fc->processed, desc->acks_to_finalize);
        }
    }

    msgs[idx++] = &desc->msg;

    return true;
}

static int fst_daq_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    FstContext *fc = static_cast<FstContext*>(handle);
    int rval = DAQ_ERROR_NOTSUP;

    if (CHECK_SUBAPI(fc, ioctl))
        rval = CALL_SUBAPI(fc, ioctl, cmd, arg, arglen);

    switch (cmd)
    {
        case DIOCTL_SET_FLOW_OPAQUE:
        {
            if (arglen != sizeof(DIOCTL_SetFlowOpaque))
                return DAQ_ERROR_INVAL;
            DIOCTL_SetFlowOpaque *sfo = static_cast<DIOCTL_SetFlowOpaque*>(arg);
            if (!sfo->msg)
                return DAQ_ERROR_INVAL;
            if (sfo->msg->owner == fc->modinst)
            {
                FstMsgDesc *desc = static_cast<FstMsgDesc*>(sfo->msg->priv);
                std::shared_ptr<FstEntry> entry = desc->entry;
                entry->flow_stats.opaque = sfo->value;
                entry->flags |= FST_ENTRY_FLAG_OPAQUE_SET;
                rval = DAQ_SUCCESS;
            }
            break;
        }
        case DIOCTL_SET_FLOW_HA_STATE:
        {
            if (arglen != sizeof(DIOCTL_FlowHAState))
                return DAQ_ERROR_INVAL;
            DIOCTL_FlowHAState *fhs = static_cast<DIOCTL_FlowHAState*>(arg);
            if (!fhs->msg || (!fhs->data && fhs->length != 0))
                return DAQ_ERROR_INVAL;
            if (fhs->msg->owner == fc->modinst)
            {
                FstMsgDesc *desc = static_cast<FstMsgDesc*>(fhs->msg->priv);
                std::shared_ptr<FstEntry> entry = desc->entry;
                if (fhs->length > 0)
                {
                    if (entry->ha_state)
                        delete[] entry->ha_state;
                    entry->ha_state = new uint8_t[fhs->length];
                    entry->ha_state_len = fhs->length;
                    memcpy(entry->ha_state, fhs->data, entry->ha_state_len);
                }
                else
                {
                    delete[] entry->ha_state;
                    entry->ha_state = nullptr;
                    entry->ha_state_len = 0;
                }
                rval = DAQ_SUCCESS;
            }
            break;
        }
        case DIOCTL_GET_FLOW_HA_STATE:
        {
            if (arglen != sizeof(DIOCTL_FlowHAState))
                return DAQ_ERROR_INVAL;
            DIOCTL_FlowHAState *fhs = static_cast<DIOCTL_FlowHAState*>(arg);
            if (!fhs->msg)
                return DAQ_ERROR_INVAL;
            if (fhs->msg->owner == fc->modinst)
            {
                FstMsgDesc *desc = static_cast<FstMsgDesc*>(fhs->msg->priv);
                std::shared_ptr<FstEntry> entry = desc->entry;
                fhs->data = entry->ha_state;
                fhs->length = entry->ha_state_len;
                rval = DAQ_SUCCESS;
            }
            break;
        }
        default:
            break;
    }

    return rval;
}

static bool process_unjudged_souls(FstContext *fc, const DAQ_Msg_t *msgs[], unsigned max_recv, unsigned &idx)
{
    if (fc->limbo.empty())
        return true;

    while (idx < max_recv && !fc->limbo.empty())
    {
        if (!process_daq_msg(fc, fc->limbo.front(), msgs, max_recv, idx))
            return false;
        fc->limbo.pop_front();
    }

    /* Corner case: If souls from limbo filled the last slot available (or there were none available to begin with),
        return false to indicate that processing was incomplete. */
    return idx < max_recv;
}

static unsigned fst_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    FstContext *fc = static_cast<FstContext*>(handle);
    unsigned idx = 0;

    *rstat = DAQ_RSTAT_OK;
    /* If there's anyone sitting in limbo, process them first. */
    if (!process_unjudged_souls(fc, msgs, max_recv, idx))
    {
        if (idx != max_recv)
            *rstat = DAQ_RSTAT_NOBUF;
    }
    /* Then, process any lost souls in purgatory. */
    if (!process_lost_souls(fc, msgs, max_recv, idx))
    {
        if (idx != max_recv)
           *rstat = DAQ_RSTAT_NOBUF;
    }
    /* If we generated any messages from limbo or purgatory, we can't call into the submodule's
        msg_receive() because it might block, so just wait for the next time around. */
    if (idx > 0)
    {
        debugf("Produced %u messages from limbo and purgatory.\n", idx);
        /* If everywhere is completely empty, return the last receive status we got from the submodule. */
        if (fc->limbo.empty() && fc->flow_table.purgatory_empty() && *rstat == DAQ_RSTAT_OK)
        {
            *rstat = fc->last_rstat;
            debugf("Finished emptying limbo and purgatory, returning original status (%d)\n", *rstat);
        }
        return idx;
    }

    /* Ok, now let's go try to get messages from the submodule. */
    const DAQ_Msg_t *orig_msgs[max_recv];
    unsigned num_receive = CALL_SUBAPI(fc, msg_receive, max_recv, orig_msgs, rstat);
    unsigned orig_idx;

    for (orig_idx = 0; orig_idx < num_receive && idx < max_recv; orig_idx++)
    {
        if (!process_daq_msg(fc, orig_msgs[orig_idx], msgs, max_recv, idx))
        {
            if (idx != max_recv)
                *rstat = DAQ_RSTAT_NOBUF;
            break;
        }
    }

    if (orig_idx < num_receive)
    {
        /* Place any stragglers in limbo. */
        while (orig_idx < num_receive)
            fc->limbo.push_back(orig_msgs[orig_idx++]);
        fc->last_rstat = *rstat;
        *rstat = DAQ_RSTAT_OK;
    }

    /* If we hit the end of file in readback mode, drain the table. */
    if (*rstat == DAQ_RSTAT_EOF)
    {
        fc->flow_table.clear();
        if (!process_lost_souls(fc, msgs, max_recv, idx))
        {
            fc->last_rstat = *rstat;
            *rstat = DAQ_RSTAT_OK;
        }
    }

    return idx;
}

static int fst_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    FstContext *fc = static_cast<FstContext*>(handle);

    if (msg->owner == fc->modinst)
    {
        FstMsgDesc *desc = static_cast<FstMsgDesc*>(msg->priv);
        std::shared_ptr<FstEntry> entry = desc->entry;

        if (fc->meta_ack_enabled)
        {
            while (desc->acks_to_finalize)
            {
                assert(!fc->held_bare_acks.empty());
                debugf("Finalizing bare ACK (%u/%zu to go)\n",
                        desc->acks_to_finalize, fc->held_bare_acks.size());
                DAQ_Msg_h bam = fc->held_bare_acks.front();
                fc->held_bare_acks.pop();
                CALL_SUBAPI(fc, msg_finalize, bam, verdict);
                desc->acks_to_finalize--;
            }
        }

        if (fc->binding_verdicts)
        {
            if (verdict == DAQ_VERDICT_WHITELIST)
                entry->flags |= FST_ENTRY_FLAG_WHITELISTED;
            else if (verdict == DAQ_VERDICT_BLACKLIST)
                entry->flags |= FST_ENTRY_FLAG_BLACKLISTED;
        }
        msg = desc->wrapped_msg;
        /* Toss the descriptor back on the free list for reuse. */
        desc->entry = nullptr;
        desc->wrapped_msg = nullptr;
        fc->pool.put_free(desc);
        if (!msg)
            return DAQ_SUCCESS;
    }

    return CALL_SUBAPI(fc, msg_finalize, msg, verdict);
}

extern "C" {
#ifdef BUILDING_SO
DAQ_SO_PUBLIC DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
DAQ_ModuleAPI_t fst_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_FST_VERSION,
    /* .name = */ "fst",
    /* .type = */ DAQ_TYPE_WRAPPER,
    /* .load = */ fst_daq_module_load,
    /* .unload = */ fst_daq_module_unload,
    /* .get_variable_descs = */ fst_daq_get_variable_descs,
    /* .instantiate = */ fst_daq_instantiate,
    /* .destroy = */ fst_daq_destroy,
    /* .set_filter = */ NULL,
    /* .start = */ fst_daq_start,
    /* .inject = */ NULL,
    /* .inject_relative = */ NULL,
    /* .interrupt = */ NULL,
    /* .stop = */ fst_daq_stop,
    /* .ioctl = */ fst_daq_ioctl,
    /* .get_stats = */ NULL,
    /* .reset_stats = */ NULL,
    /* .get_snaplen = */ NULL,
    /* .get_capabilities = */ NULL,
    /* .get_datalink_type = */ NULL,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ fst_daq_msg_receive,
    /* .msg_finalize = */ fst_daq_msg_finalize,
    /* .get_msg_pool_info = */ NULL,
};
}

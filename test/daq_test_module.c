#include <daq_test_module.h>

static int daq_test_prepare(const DAQ_BaseAPI_t *base_api)
{
    return DAQ_SUCCESS;
}

static int daq_test_initialize(const DAQ_ModuleConfig_h config, void **ctxt_ptr, char *errbuf, size_t len)
{
    return DAQ_SUCCESS;
}

static int daq_test_start(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    return DAQ_SUCCESS;
}

static int daq_test_breakloop(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_stop(void *handle)
{
    return DAQ_SUCCESS;
}

void daq_test_shutdown(void *handle)
{
}

DAQ_State daq_test_check_status(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_stats(void *handle, DAQ_Stats_t *stats)
{
    return DAQ_SUCCESS;
}

void daq_test_reset_stats(void *handle)
{
}

static int daq_test_get_snaplen(void *handle)
{
    return DAQ_SUCCESS;
}

uint32_t daq_test_get_capabilities(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_datalink_type(void *handle)
{
    return DAQ_SUCCESS;
}

const char *daq_test_get_errbuf(void *handle)
{
    return DAQ_SUCCESS;
}

void daq_test_set_errbuf(void *handle, const char *string)
{
}

static int daq_test_get_device_index(void *handle, const char *device)
{
    return DAQ_SUCCESS;
}

static int daq_test_msg_receive(void *handle, const DAQ_Msg_t **msgptr)
{
    return DAQ_SUCCESS;
}

static int daq_test_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    return DAQ_SUCCESS;
}

DAQ_PktHdr_t *daq_test_packet_header_from_msg(void *handle, const DAQ_Msg_t *msg)
{
    return NULL;
}

const uint8_t *daq_test_packet_data_from_msg(void *handle, const DAQ_Msg_t *msg)
{
    return NULL;
}


DAQ_ModuleAPI_t test_module =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ TEST_MODULE_VERSION,
    /* .name = */ TEST_MODULE_NAME,
    /* .type = */ TEST_MODULE_TYPE,
    /* .prepare = */ daq_test_prepare,
    /* .get_variable_descs = */ NULL,
    /* .initialize = */ daq_test_initialize,
    /* .set_filter = */ NULL,
    /* .start = */ daq_test_start,
    /* .inject = */ daq_test_inject,
    /* .breakloop = */ daq_test_breakloop,
    /* .stop = */ daq_test_stop,
    /* .shutdown = */ daq_test_shutdown,
    /* .check_status = */ daq_test_check_status,
    /* .get_stats = */ daq_test_get_stats,
    /* .reset_stats = */ daq_test_reset_stats,
    /* .get_snaplen = */ daq_test_get_snaplen,
    /* .get_capabilities = */ daq_test_get_capabilities,
    /* .get_datalink_type = */ daq_test_get_datalink_type,
    /* .get_errbuf = */ daq_test_get_errbuf,
    /* .set_errbuf = */ daq_test_set_errbuf,
    /* .get_device_index = */ daq_test_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .query_flow = */ NULL,
    /* .msg_receive = */ daq_test_msg_receive,
    /* .msg_finalize = */ daq_test_msg_finalize,
    /* .packet_header_from_msg = */ daq_test_packet_header_from_msg,
    /* .packet_data_from_msg = */ daq_test_packet_data_from_msg,
};


#include "daq_test_module.h"

#include <daq_dlt.h>

static int daq_test_prepare(const DAQ_BaseAPI_t *base_api)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = NULL;
    return 0;
}

static int daq_test_initialize(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    return DAQ_SUCCESS;
}

static int daq_test_start(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_inject(void *handle, DAQ_Msg_h msg, const uint8_t *packet_data, uint32_t len, int reverse)
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

static void daq_test_shutdown(void *handle)
{
}

static int daq_test_get_stats(void *handle, DAQ_Stats_t *stats)
{
    return DAQ_SUCCESS;
}

static void daq_test_reset_stats(void *handle)
{
}

static int daq_test_get_snaplen(void *handle)
{
    return DAQ_SUCCESS;
}

static uint32_t daq_test_get_capabilities(void *handle)
{
    return DAQ_SUCCESS;
}

static int daq_test_get_datalink_type(void *handle)
{
    return DLT_NULL;
}

static unsigned daq_test_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    return 0;
}

static int daq_test_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    return DAQ_SUCCESS;
}


DAQ_ModuleAPI_t test_module =
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ TEST_MODULE_VERSION,
    /* .name = */ TEST_MODULE_NAME,
    /* .type = */ TEST_MODULE_TYPE,
    /* .prepare = */ daq_test_prepare,
    /* .get_variable_descs = */ daq_test_get_variable_descs,
    /* .initialize = */ daq_test_initialize,
    /* .set_filter = */ NULL,
    /* .start = */ daq_test_start,
    /* .inject = */ daq_test_inject,
    /* .breakloop = */ daq_test_breakloop,
    /* .stop = */ daq_test_stop,
    /* .shutdown = */ daq_test_shutdown,
    /* .get_stats = */ daq_test_get_stats,
    /* .reset_stats = */ daq_test_reset_stats,
    /* .get_snaplen = */ daq_test_get_snaplen,
    /* .get_capabilities = */ daq_test_get_capabilities,
    /* .get_datalink_type = */ daq_test_get_datalink_type,
    /* .get_device_index = */ NULL,
    /* .modify_flow = */ NULL,
    /* .query_flow = */ NULL,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .dp_add_dc = */ NULL,
    /* .msg_receive = */ daq_test_msg_receive,
    /* .msg_finalize = */ daq_test_msg_finalize,
    /* .get_msg_pool_info = */ NULL,
};


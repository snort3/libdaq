/*
** Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include <cmocka.h>

#include "daq.h"
#include "daq_dlt.h"
#include "daq_module_api.h"

extern const DAQ_ModuleAPI_t dump_daq_module_data;

#define MOCK_MODULE_NAME    "mock_source"
#define MOCK_MODULE_VERSION 1
#define MOCK_SNAPLEN        1518
#define MOCK_BATCH_SIZE     16
#define MOCK_MAX_PKT_SIZE   1500

#define PCAP_MAGIC          0xa1b2c3d4
#define PCAP_FILE_HDR_SIZE  24
#define PCAP_REC_HDR_SIZE   16

/* Feed configuration for the mock source module, set by each test before
 * starting the instance. */
static struct
{
    unsigned total;     /* Total number of packets msg_receive will produce */
    uint32_t pkt_size;  /* Size of each packet produced */
    unsigned fed;       /* Number of packets produced so far */
} mock_feed;

static DAQ_Msg_t mock_msgs[MOCK_BATCH_SIZE];
static DAQ_PktHdr_t mock_pkthdrs[MOCK_BATCH_SIZE];
static uint8_t mock_pktdata[MOCK_BATCH_SIZE][MOCK_MAX_PKT_SIZE];
static DAQ_ModuleInstance_h mock_modinst;

static void mock_feed_setup(unsigned total, uint32_t pkt_size)
{
    mock_feed.total = total;
    mock_feed.pkt_size = pkt_size;
    mock_feed.fed = 0;
}

static int mock_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    return DAQ_SUCCESS;
}

static int mock_daq_module_unload(void)
{
    return DAQ_SUCCESS;
}

static int mock_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = NULL;
    return 0;
}

static int mock_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
    mock_modinst = modinst;
    return DAQ_SUCCESS;
}

static void mock_daq_destroy(void *handle)
{
}

static int mock_daq_start(void *handle)
{
    return DAQ_SUCCESS;
}

static int mock_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    return DAQ_SUCCESS;
}

static int mock_daq_stop(void *handle)
{
    return DAQ_SUCCESS;
}

static int mock_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    memset(stats, 0, sizeof(*stats));
    return DAQ_SUCCESS;
}

static void mock_daq_reset_stats(void *handle)
{
}

static int mock_daq_get_snaplen(void *handle)
{
    return MOCK_SNAPLEN;
}

static uint32_t mock_daq_get_capabilities(void *handle)
{
    return 0;
}

static int mock_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static unsigned mock_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    unsigned batch = (max_recv > MOCK_BATCH_SIZE) ? MOCK_BATCH_SIZE : max_recv;
    unsigned count = 0;

    while (count < batch && mock_feed.fed < mock_feed.total)
    {
        DAQ_Msg_t *msg = &mock_msgs[count];
        DAQ_PktHdr_t *pkthdr = &mock_pkthdrs[count];

        memset(pkthdr, 0, sizeof(*pkthdr));
        pkthdr->ts.tv_sec = 1700000000 + mock_feed.fed;
        pkthdr->ts.tv_usec = mock_feed.fed % 1000000;
        pkthdr->pktlen = mock_feed.pkt_size;
        pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;

        memset(mock_pktdata[count], (int) (mock_feed.fed & 0xff), mock_feed.pkt_size);

        msg->hdr = pkthdr;
        msg->hdr_len = sizeof(*pkthdr);
        msg->data = mock_pktdata[count];
        msg->data_len = mock_feed.pkt_size;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->owner = mock_modinst;
        msg->priv = NULL;

        msgs[count] = msg;
        count++;
        mock_feed.fed++;
    }

    *rstat = (mock_feed.fed >= mock_feed.total) ? DAQ_RSTAT_EOF : DAQ_RSTAT_OK;
    return count;
}

static int mock_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    return DAQ_SUCCESS;
}

static const DAQ_ModuleAPI_t mock_module =
{
    .api_version = DAQ_MODULE_API_VERSION,
    .api_size = sizeof(DAQ_ModuleAPI_t),
    .module_version = MOCK_MODULE_VERSION,
    .name = MOCK_MODULE_NAME,
    .type = DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE,
    .load = mock_daq_module_load,
    .unload = mock_daq_module_unload,
    .get_variable_descs = mock_daq_get_variable_descs,
    .instantiate = mock_daq_instantiate,
    .destroy = mock_daq_destroy,
    .start = mock_daq_start,
    .inject = mock_daq_inject,
    .stop = mock_daq_stop,
    .get_stats = mock_daq_get_stats,
    .reset_stats = mock_daq_reset_stats,
    .get_snaplen = mock_daq_get_snaplen,
    .get_capabilities = mock_daq_get_capabilities,
    .get_datalink_type = mock_daq_get_datalink_type,
    .msg_receive = mock_daq_msg_receive,
    .msg_finalize = mock_daq_msg_finalize,
};

static DAQ_Module_h static_modules[] =
{
    &mock_module,
    &dump_daq_module_data,
    NULL
};

/*
 * PCAP savefile inspection helpers
 */

/* Returns the number of packet records in a PCAP savefile, or -1 if the file
 * does not exist or is malformed. */
static int count_pcap_packets(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    uint8_t file_hdr[PCAP_FILE_HDR_SIZE];
    if (fread(file_hdr, 1, sizeof(file_hdr), fp) != sizeof(file_hdr))
    {
        fclose(fp);
        return -1;
    }

    uint32_t magic;
    memcpy(&magic, file_hdr, sizeof(magic));
    if (magic != PCAP_MAGIC)
    {
        fclose(fp);
        return -1;
    }

    int count = 0;
    uint8_t rec_hdr[PCAP_REC_HDR_SIZE];
    size_t nread;
    while ((nread = fread(rec_hdr, 1, sizeof(rec_hdr), fp)) == sizeof(rec_hdr))
    {
        uint32_t caplen;
        memcpy(&caplen, rec_hdr + 8, sizeof(caplen));
        if (caplen > MOCK_SNAPLEN || fseek(fp, caplen, SEEK_CUR) != 0)
        {
            fclose(fp);
            return -1;
        }
        count++;
    }

    if (nread != 0)
    {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return count;
}

static long file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    return (long) st.st_size;
}

static bool file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/*
 * Test fixture: each test runs in its own temporary directory so the dump
 * module's output files can be inspected and cleaned up safely.
 */

static char original_cwd[4096];

static int testdir_setup(void **state)
{
    char tmpl[] = "dump_module_test_XXXXXX";

    if (!getcwd(original_cwd, sizeof(original_cwd)))
        return -1;
    if (!mkdtemp(tmpl))
        return -1;
    if (chdir(tmpl) != 0)
        return -1;

    char *dirname = strdup(tmpl);
    if (!dirname)
        return -1;
    *state = dirname;
    return 0;
}

static int testdir_teardown(void **state)
{
    char *dirname = (char *) *state;

    DIR *dir = opendir(".");
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
                unlink(entry->d_name);
        }
        closedir(dir);
    }

    if (chdir(original_cwd) != 0)
        return -1;
    rmdir(dirname);
    free(dirname);
    return 0;
}

/*
 * Instance bringup/rundown helpers
 */

typedef struct
{
    const char *key;
    const char *value;
} TestVariable;

static int instantiate_dump_stack(const TestVariable *vars, DAQ_Instance_h *instance, char *errbuf, size_t errbuf_len)
{
    DAQ_Config_h cfg;
    DAQ_ModuleConfig_h modcfg;
    int rval;

    rval = daq_config_new(&cfg);
    assert_int_equal(rval, DAQ_SUCCESS);
    daq_config_set_input(cfg, "mock");
    daq_config_set_snaplen(cfg, MOCK_SNAPLEN);
    daq_config_set_timeout(cfg, 0);

    DAQ_Module_h module = daq_find_module(MOCK_MODULE_NAME);
    assert_non_null(module);
    rval = daq_module_config_new(&modcfg, module);
    assert_int_equal(rval, DAQ_SUCCESS);
    rval = daq_config_push_module_config(cfg, modcfg);
    assert_int_equal(rval, DAQ_SUCCESS);

    module = daq_find_module("dump");
    assert_non_null(module);
    rval = daq_module_config_new(&modcfg, module);
    assert_int_equal(rval, DAQ_SUCCESS);
    for (; vars && vars->key; vars++)
    {
        rval = daq_module_config_set_variable(modcfg, vars->key, vars->value);
        assert_int_equal(rval, DAQ_SUCCESS);
    }
    rval = daq_config_push_module_config(cfg, modcfg);
    assert_int_equal(rval, DAQ_SUCCESS);

    rval = daq_instance_instantiate(cfg, instance, errbuf, errbuf_len);
    daq_config_destroy(cfg);

    return rval;
}

static DAQ_Instance_h bringup_dump_stack(const TestVariable *vars)
{
    DAQ_Instance_h instance = NULL;
    char errbuf[256];

    int rval = instantiate_dump_stack(vars, &instance, errbuf, sizeof(errbuf));
    assert_int_equal(rval, DAQ_SUCCESS);
    assert_non_null(instance);
    return instance;
}

/* Receive all packets offered by the mock source module and finalize each
 * with the given verdict. */
static void process_all_packets(DAQ_Instance_h instance, DAQ_Verdict verdict)
{
    DAQ_Msg_h msgs[MOCK_BATCH_SIZE];
    DAQ_RecvStatus rstat;

    do
    {
        unsigned num_recv = daq_instance_msg_receive(instance, MOCK_BATCH_SIZE, msgs, &rstat);
        for (unsigned idx = 0; idx < num_recv; idx++)
        {
            int rval = daq_instance_msg_finalize(instance, msgs[idx], verdict);
            assert_int_equal(rval, DAQ_SUCCESS);
        }
    } while (rstat == DAQ_RSTAT_OK);
    assert_int_equal(rstat, DAQ_RSTAT_EOF);
}

/*
 * Tests
 */

/* Without any rolling variables, all packets land in a single file (the
 * original behavior). */
static void test_no_rolling_single_file(void **state)
{
    DAQ_Instance_h instance = bringup_dump_stack(NULL);

    mock_feed_setup(25, 100);
    assert_int_equal(daq_instance_start(instance), DAQ_SUCCESS);
    process_all_packets(instance, DAQ_VERDICT_PASS);
    assert_int_equal(daq_instance_stop(instance), DAQ_SUCCESS);
    daq_instance_destroy(instance);

    assert_int_equal(count_pcap_packets("inline-out.pcap"), 25);
    assert_false(file_exists("inline-out.pcap.1"));
    assert_false(file_exists("inline-in.pcap"));
}

/* Rolling by packet count splits the output across multiple files, honoring
 * a custom base filename. */
static void test_roll_by_packet_count(void **state)
{
    const TestVariable vars[] = {
        { "file", "custom-out.pcap" },
        { "roll-pkts", "10" },
        { NULL, NULL }
    };
    DAQ_Instance_h instance = bringup_dump_stack(vars);

    mock_feed_setup(25, 100);
    assert_int_equal(daq_instance_start(instance), DAQ_SUCCESS);
    process_all_packets(instance, DAQ_VERDICT_PASS);
    assert_int_equal(daq_instance_stop(instance), DAQ_SUCCESS);
    daq_instance_destroy(instance);

    assert_int_equal(count_pcap_packets("custom-out.pcap"), 10);
    assert_int_equal(count_pcap_packets("custom-out.pcap.1"), 10);
    assert_int_equal(count_pcap_packets("custom-out.pcap.2"), 5);
    assert_false(file_exists("custom-out.pcap.3"));
}

/* Rolling by file size: each file except the last must have reached the size
 * limit, and no packets may be lost across the roll boundaries. */
static void test_roll_by_size(void **state)
{
    const TestVariable vars[] = {
        { "roll-size", "1" },
        { NULL, NULL }
    };
    DAQ_Instance_h instance = bringup_dump_stack(vars);

    const unsigned total_pkts = 1600;
    const uint32_t pkt_size = 1400;
    const unsigned pkts_per_file = 741;

    mock_feed_setup(total_pkts, pkt_size);
    assert_int_equal(daq_instance_start(instance), DAQ_SUCCESS);
    process_all_packets(instance, DAQ_VERDICT_PASS);
    assert_int_equal(daq_instance_stop(instance), DAQ_SUCCESS);
    daq_instance_destroy(instance);

    assert_int_equal(count_pcap_packets("inline-out.pcap"), pkts_per_file);
    assert_int_equal(count_pcap_packets("inline-out.pcap.1"), pkts_per_file);
    assert_int_equal(count_pcap_packets("inline-out.pcap.2"), total_pkts - 2 * pkts_per_file);
    assert_false(file_exists("inline-out.pcap.3"));

    assert_true(file_size("inline-out.pcap") >= 1024 * 1024);
    assert_true(file_size("inline-out.pcap.1") >= 1024 * 1024);
    assert_true(file_size("inline-out.pcap.2") < 1024 * 1024);
}

/* When both limits are configured, whichever is hit first triggers the roll. */
static void test_roll_both_limits(void **state)
{
    const TestVariable vars[] = {
        { "roll-size", "1" },
        { "roll-pkts", "5" },
        { NULL, NULL }
    };
    DAQ_Instance_h instance = bringup_dump_stack(vars);

    mock_feed_setup(12, 100);
    assert_int_equal(daq_instance_start(instance), DAQ_SUCCESS);
    process_all_packets(instance, DAQ_VERDICT_PASS);
    assert_int_equal(daq_instance_stop(instance), DAQ_SUCCESS);
    daq_instance_destroy(instance);

    assert_int_equal(count_pcap_packets("inline-out.pcap"), 5);
    assert_int_equal(count_pcap_packets("inline-out.pcap.1"), 5);
    assert_int_equal(count_pcap_packets("inline-out.pcap.2"), 2);
}

/* The RX dump file rolls independently of the TX dump file.  Blocked packets
 * are written only to the RX file, so it should roll while the TX file stays
 * empty and never rolls. */
static void test_rx_rolls_independently(void **state)
{
    const TestVariable vars[] = {
        { "dump-rx", NULL },
        { "roll-pkts", "10" },
        { NULL, NULL }
    };
    DAQ_Instance_h instance = bringup_dump_stack(vars);

    mock_feed_setup(25, 100);
    assert_int_equal(daq_instance_start(instance), DAQ_SUCCESS);
    process_all_packets(instance, DAQ_VERDICT_BLOCK);
    assert_int_equal(daq_instance_stop(instance), DAQ_SUCCESS);
    daq_instance_destroy(instance);

    assert_int_equal(count_pcap_packets("inline-in.pcap"), 10);
    assert_int_equal(count_pcap_packets("inline-in.pcap.1"), 10);
    assert_int_equal(count_pcap_packets("inline-in.pcap.2"), 5);

    assert_int_equal(count_pcap_packets("inline-out.pcap"), 0);
    assert_false(file_exists("inline-out.pcap.1"));
}

/* Packets written via the inject path also count toward the roll limits. */
static void test_inject_rolling(void **state)
{
    const TestVariable vars[] = {
        { "roll-pkts", "3" },
        { NULL, NULL }
    };
    DAQ_Instance_h instance = bringup_dump_stack(vars);

    mock_feed_setup(0, 0);
    assert_int_equal(daq_instance_start(instance), DAQ_SUCCESS);

    uint8_t pktdata[100];
    memset(pktdata, 0xa5, sizeof(pktdata));
    DAQ_PktHdr_t pkthdr;
    memset(&pkthdr, 0, sizeof(pkthdr));
    pkthdr.ts.tv_sec = 1700000000;
    pkthdr.pktlen = sizeof(pktdata);

    for (int i = 0; i < 7; i++)
    {
        int rval = daq_instance_inject(instance, DAQ_MSG_TYPE_PACKET, &pkthdr, pktdata, sizeof(pktdata));
        assert_int_equal(rval, DAQ_SUCCESS);
    }

    assert_int_equal(daq_instance_stop(instance), DAQ_SUCCESS);
    daq_instance_destroy(instance);

    assert_int_equal(count_pcap_packets("inline-out.pcap"), 3);
    assert_int_equal(count_pcap_packets("inline-out.pcap.1"), 3);
    assert_int_equal(count_pcap_packets("inline-out.pcap.2"), 1);
}

/* A new instance starts rolling over from the base filename rather than
 * continuing from where a previous instance left off. */
static void test_new_instance_restarts_rolling(void **state)
{
    const TestVariable vars[] = {
        { "roll-pkts", "10" },
        { NULL, NULL }
    };
    DAQ_Instance_h instance = bringup_dump_stack(vars);

    mock_feed_setup(25, 100);
    assert_int_equal(daq_instance_start(instance), DAQ_SUCCESS);
    process_all_packets(instance, DAQ_VERDICT_PASS);
    assert_int_equal(daq_instance_stop(instance), DAQ_SUCCESS);
    daq_instance_destroy(instance);

    assert_int_equal(count_pcap_packets("inline-out.pcap"), 10);
    assert_int_equal(count_pcap_packets("inline-out.pcap.2"), 5);

    instance = bringup_dump_stack(vars);
    mock_feed_setup(5, 100);
    assert_int_equal(daq_instance_start(instance), DAQ_SUCCESS);
    process_all_packets(instance, DAQ_VERDICT_PASS);
    assert_int_equal(daq_instance_stop(instance), DAQ_SUCCESS);
    daq_instance_destroy(instance);

    assert_int_equal(count_pcap_packets("inline-out.pcap"), 5);
    assert_int_equal(count_pcap_packets("inline-out.pcap.1"), 10);
    assert_int_equal(count_pcap_packets("inline-out.pcap.2"), 5);
}

/* Invalid rolling variable values must be rejected at instantiation time. */
static void test_invalid_variables(void **state)
{
    static const TestVariable invalid_cases[][2] = {
        { { "roll-size", "abc" }, { NULL, NULL } },
        { { "roll-size", "0" }, { NULL, NULL } },
        { { "roll-size", "10abc" }, { NULL, NULL } },
        { { "roll-size", "-1" }, { NULL, NULL } },
        { { "roll-size", "" }, { NULL, NULL } },
        { { "roll-pkts", "xyz" }, { NULL, NULL } },
        { { "roll-pkts", "0" }, { NULL, NULL } },
        { { "roll-pkts", "-5" }, { NULL, NULL } },
    };

    for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]); i++)
    {
        DAQ_Instance_h instance = NULL;
        char errbuf[256];

        int rval = instantiate_dump_stack(invalid_cases[i], &instance, errbuf, sizeof(errbuf));
        assert_int_equal(rval, DAQ_ERROR_INVAL);
        assert_null(instance);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_no_rolling_single_file, testdir_setup, testdir_teardown),
        cmocka_unit_test_setup_teardown(test_roll_by_packet_count, testdir_setup, testdir_teardown),
        cmocka_unit_test_setup_teardown(test_roll_by_size, testdir_setup, testdir_teardown),
        cmocka_unit_test_setup_teardown(test_roll_both_limits, testdir_setup, testdir_teardown),
        cmocka_unit_test_setup_teardown(test_rx_rolls_independently, testdir_setup, testdir_teardown),
        cmocka_unit_test_setup_teardown(test_inject_rolling, testdir_setup, testdir_teardown),
        cmocka_unit_test_setup_teardown(test_new_instance_restarts_rolling, testdir_setup, testdir_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_variables, testdir_setup, testdir_teardown),
    };

    int rval = daq_load_static_modules(static_modules);
    assert_int_equal(rval, 2);

    return cmocka_run_group_tests(tests, NULL, NULL);
}

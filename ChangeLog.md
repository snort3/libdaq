2026-07-05: 3.0.28

* api: add DIOCTL_GET_DAQ_COUNTERS_SUMMARY for generic DAQ counter export
* api: QinQ outer vlan tag addition
* build: add fourth digit to daq version field
* daq: add drop_reason_str to DAQ_FlowStats_t

2026-03-17: 3.0.27

* libdaq: add a ChangeLog.md file to track changes

2026-03-02: 3.0.26

* pcap: add basic rewind feature upon reaching EOF (excluding stdin and pcapng)

2026-02-28: 3.0.25

* copyright: update year to 2026

2025-12-08: 3.0.24

* api: update dioctl daqSnort latency common changes

2025-11-25: 3.0.23

* api: add TCP flag in DAQ flow stats

2025-11-07: 3.0.22

* api: add drop reason in DAQ flow stats

2025-08-11: 3.0.21

* api: add support for handling DIOCTL_SET_INJECT_DROP

2025-07-02: 3.0.20

* decode: add check for IPv4 fragmentation for decode_ip
* example: add IP configs for other systems

2025-03-12: 3.0.19

* api: add DIOCTL_SET_SNORT_LATENCY dioctl for snort latency configuration
* ci: fix CSCwm35781 build pipeline issues
* copyright: update year to 2025

2025-01-21: 3.0.18

* api: add DIOCTL_GET_SNORT_LATENCY dioctl for retrieving snort latency data

2024-10-21: 3.0.17

* daq_netmap: fix build on Linux with non-system headers
* example: support snap encapsulation

2024-07-30: 3.0.16

* daq: add outstanding counter

2024-06-03: 3.0.15

* api: add DIOCTL_GET_CPU_PROFILE_DATA ioctl to get CPU profile data

2024-01-16: 3.0.14

* copyright: update year to 2024

2023-11-08: 3.0.13

* daq: send hardware packets received counter
* daq: fix incorrect counters caused by data plane counters reset

2023-06-20: 3.0.12

* api: add daq_msg_get_priv_data to get pointer to private data
* api: add DIOCTL_GET_PRIV_DATA_LEN ioctl to get private data length
* trace: don't log message when DIOCTL_PRIV_DATA_LEN ioctl is seen

2023-02-24: 3.0.11

* copyright: update for year 2023

2022-12-05: 3.0.10

* geneve: add geneve decode capability flag

2022-06-15: 3.0.9

* libdaq: add new flag to skip Elephant flow processing

2022-06-02: 3.0.8

* gwlb: create wrapper DAQ for GWLB environment
* gwlb: do not build gwlb if afpacket is not also built

2022-05-04: 3.0.7

* api: add support for 32-bit address space ID and tenant ID

2022-01-25: 3.0.6

* copyright: update year to 2022

2021-07-26: 3.0.5

* api: introduce bidirectional flag for expected session

2021-05-19: 3.0.4

* api: support for inner flow NAT

2021-04-25: 3.0.3

* api: add logging optional flag for flow stats
* daq_fst: fix bug in passing foreign dynamic metadata from wrapped messages
* copyright: update to year 2021

2021-03-27: 3.0.2

* daq_savefile: add optimized PCAP savefile readback DAQ module
* daqtest: add ASCII data dump (-X)
* daq_fst: pass through foreign dynamic metadata from wrapped messages
* build: bump version to 3.0.2
* api: remove the RETRY verdict

2021-03-12: 3.0.1

* api: add a comprehensive version number to the DAQ common definitions
* api: rename Flow_Stats_t to DAQ_FlowStats_t and clean up field names

2021-01-14: 3.0.0

* api: add checksum offset and checksum error status to DecodeData metadata
* api: add TCP option observations to DecodeData metadata
* daq_fst: add variable to ignore bad checksums ('ignore_checksums')
* daqtest: add packet number to packet decode output
* doc: start fleshing out the README for LibDAQ 3.x
* decode: always set payload offset to the end of the last header successfully decoded
* decode: decode and loosely validate options in the TCP header
* decode: improve IPv6 extension header decoding
* decode: internalize ethertype definitions and expand recognized VLAN types
* decode: truncate remaining length when Ethernet trailers are detected during IPv6 decoding
* build: bump to 3.0.0 final
* build: correct the project name to be libdaq
* build: force DAQ modules to still be installed in $libdir/daq
* daqtest: fix ignoring checksum errors for all packets

For changes prior to version 3.0.0, please refer to ChangeLog-2.x.

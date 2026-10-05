#ifndef KXFLOW_EVENT_H
#define KXFLOW_EVENT_H

#include <linux/types.h>

#define KXFLOW_EVENT_PACKET 0
#define KXFLOW_EVENT_ALERT  1

#define KXFLOW_SEVERITY_INFO     0
#define KXFLOW_SEVERITY_LOW      1
#define KXFLOW_SEVERITY_MEDIUM   2
#define KXFLOW_SEVERITY_HIGH     3
#define KXFLOW_SEVERITY_CRITICAL 4

struct kxflow_event
{
    __u64 timestamp_ns;

    __u32 src_ip;
    __u32 dst_ip;

    __u16 src_port;
    __u16 dst_port;

    __u8 protocol;
    __u8 action;

    __u32 packet_size;

    __u8 event_type;
    __u8 severity;
};


struct flow_key
{
    __u32 src_ip;
    __u32 dst_ip;

    __u16 src_port;
    __u16 dst_port;

    __u8 protocol;
};


struct flow_stats
{
    __u64 packet_count;
    __u64 byte_count;

    __u64 first_seen_ns;
    __u64 last_seen_ns;
};


struct scan_port_key
{
    __u32 src_ip;
    __u16 dst_port;
    __u64 window_id;
};


struct scan_stats
{
    __u32 unique_ports;
    __u8 alert_sent;
};

#endif

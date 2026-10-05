#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "kxflow_event.h"

#define SCAN_WINDOW_NS      10000000000ULL
#define SCAN_PORT_THRESHOLD 10

/* ---------------------------------------------------------
 * Flow tracking
 * --------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flows SEC(".maps");


/* ---------------------------------------------------------
 * Port-scan tracking
 * --------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct scan_port_key);
    __type(value, __u8);
} scan_ports SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct scan_stats);
} scan_sources SEC(".maps");


/* ---------------------------------------------------------
 * Blocked source IPs
 *
 * Source IP -> timestamp when blocked
 * --------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} blocked_sources SEC(".maps");


/* ---------------------------------------------------------
 * Ring Buffer
 * --------------------------------------------------------- */

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


/* ---------------------------------------------------------
 * Send normal packet telemetry
 * --------------------------------------------------------- */

static __always_inline void send_packet_event(
    __u64 timestamp,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 src_port,
    __u16 dst_port,
    __u8 protocol,
    __u32 packet_size)
{
    struct kxflow_event *event;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0
    );

    if (!event)
        return;

    event->timestamp_ns = timestamp;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->protocol = protocol;
    event->action = XDP_PASS;
    event->packet_size = packet_size;
    event->event_type = KXFLOW_EVENT_PACKET;
    event->severity = KXFLOW_SEVERITY_INFO;

    bpf_ringbuf_submit(event, 0);
}


/* ---------------------------------------------------------
 * Send security alert
 * --------------------------------------------------------- */

static __always_inline void send_alert_event(
    __u64 timestamp,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 dst_port,
    __u8 protocol,
    __u8 action,
    __u8 severity)
{
    struct kxflow_event *event;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0
    );

    if (!event)
        return;

    event->timestamp_ns = timestamp;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = 0;
    event->dst_port = dst_port;
    event->protocol = protocol;
    event->action = action;
    event->packet_size = 0;
    event->event_type = KXFLOW_EVENT_ALERT;
    event->severity = severity;

    bpf_ringbuf_submit(event, 0);
}


/* ---------------------------------------------------------
 * TCP port-scan detection
 *
 * 10 unique destination ports
 * within a 10-second window.
 *
 * When threshold is reached:
 *
 *     detect
 *       ↓
 *     block source
 *       ↓
 *     send ONE alert
 *       ↓
 *     DROP current packet
 * --------------------------------------------------------- */

static __always_inline int detect_port_scan(
    __u64 now,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 dst_port)
{
    __u64 window_id = now / SCAN_WINDOW_NS;

    struct scan_port_key port_key = {
        .src_ip = src_ip,
        .dst_port = dst_port,
        .window_id = window_id
    };

    __u8 value = 1;

    /*
     * Already observed this source/port/window.
     */
    if (bpf_map_lookup_elem(&scan_ports, &port_key))
        return 0;

    /*
     * Record this unique destination port.
     */
    bpf_map_update_elem(
        &scan_ports,
        &port_key,
        &value,
        BPF_ANY
    );


    /*
     * Find source scan statistics.
     */
    struct scan_stats *stats;

    stats = bpf_map_lookup_elem(
        &scan_sources,
        &src_ip
    );

    if (!stats)
    {
        struct scan_stats new_stats = {
            .unique_ports = 1,
            .alert_sent = 0
        };

        bpf_map_update_elem(
            &scan_sources,
            &src_ip,
            &new_stats,
            BPF_ANY
        );

        return 0;
    }


    /*
     * Increment unique destination port count.
     */
    stats->unique_ports++;


    /*
     * Threshold reached.
     *
     * alert_sent prevents repeated detection alerts
     * for the same source.
     */
    if (stats->unique_ports >= SCAN_PORT_THRESHOLD &&
        stats->alert_sent == 0)
    {
        __u64 block_time = now;

        /*
         * Mark source as blocked.
         */
        bpf_map_update_elem(
            &blocked_sources,
            &src_ip,
            &block_time,
            BPF_ANY
        );

        /*
         * Prevent future detection alerts.
         */
        stats->alert_sent = 1;

        /*
         * Send exactly ONE security alert.
         *
         * dst_port is the actual port that triggered
         * the threshold.
         */
        send_alert_event(
            now,
            src_ip,
            dst_ip,
            dst_port,
            IPPROTO_TCP,
            XDP_DROP,
            KXFLOW_SEVERITY_HIGH
        );

        /*
         * Tell caller that this packet must be dropped.
         */
        return 1;
    }

    return 0;
}


/* ---------------------------------------------------------
 * Main XDP program
 * --------------------------------------------------------- */

SEC("xdp")
int kxflow_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    /*
     * Ethernet bounds check.
     */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /*
     * IPv4 only for now.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph =
        (void *)(eth + 1);

    /*
     * IPv4 bounds check.
     */
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;

    __u8 protocol = iph->protocol;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    /*
     * ------------------------------------------------------
     * TCP parsing
     * ------------------------------------------------------
     */

    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp =
            (void *)iph + (iph->ihl * 4);

        /*
         * TCP bounds check.
         */
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);


        /*
         * --------------------------------------------------
         * Check whether source is already blocked.
         *
         * IMPORTANT:
         * TCP ports are parsed BEFORE this check.
         *
         * Blocked packets are silently dropped.
         * NO alert is generated here.
         * --------------------------------------------------
         */

        __u64 *blocked =
            bpf_map_lookup_elem(
                &blocked_sources,
                &src_ip
            );

        if (blocked)
            return XDP_DROP;


        /*
         * --------------------------------------------------
         * Flow tracking
         * --------------------------------------------------
         */

        struct flow_key key = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = protocol
        };

        struct flow_stats *flow;

        flow = bpf_map_lookup_elem(
            &flows,
            &key
        );

        if (flow)
        {
            flow->packet_count++;

            flow->byte_count +=
                (__u64)((char *)data_end -
                        (char *)data);

            flow->last_seen_ns = now;
        }
        else
        {
            struct flow_stats new_flow = {
                .packet_count = 1,
                .byte_count =
                    (__u64)((char *)data_end -
                            (char *)data),
                .first_seen_ns = now,
                .last_seen_ns = now
            };

            bpf_map_update_elem(
                &flows,
                &key,
                &new_flow,
                BPF_ANY
            );
        }


        /*
         * --------------------------------------------------
         * Port-scan detection
         * --------------------------------------------------
         */

        int scan_detected =
            detect_port_scan(
                now,
                src_ip,
                dst_ip,
                dst_port
            );

        /*
         * Threshold reached.
         *
         * detect_port_scan() already:
         *   - added source to blocklist
         *   - sent ONE alert
         *
         * Now immediately drop the triggering packet.
         */
        if (scan_detected)
            return XDP_DROP;
    }


    /*
     * ------------------------------------------------------
     * UDP parsing
     * ------------------------------------------------------
     */

    else if (protocol == IPPROTO_UDP)
    {
        struct udphdr *udp =
            (void *)iph + (iph->ihl * 4);

        /*
         * UDP bounds check.
         */
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);


        /*
         * Block already-blacklisted sources.
         *
         * No alert.
         */
        __u64 *blocked =
            bpf_map_lookup_elem(
                &blocked_sources,
                &src_ip
            );

        if (blocked)
            return XDP_DROP;


        /*
         * Flow tracking.
         */

        struct flow_key key = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = protocol
        };

        struct flow_stats *flow;

        flow = bpf_map_lookup_elem(
            &flows,
            &key
        );

        if (flow)
        {
            flow->packet_count++;

            flow->byte_count +=
                (__u64)((char *)data_end -
                        (char *)data);

            flow->last_seen_ns = now;
        }
        else
        {
            struct flow_stats new_flow = {
                .packet_count = 1,
                .byte_count =
                    (__u64)((char *)data_end -
                            (char *)data),
                .first_seen_ns = now,
                .last_seen_ns = now
            };

            bpf_map_update_elem(
                &flows,
                &key,
                &new_flow,
                BPF_ANY
            );
        }
    }


    /*
     * ------------------------------------------------------
     * Normal packet telemetry
     * ------------------------------------------------------
     */

    send_packet_event(
        now,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        (__u32)((char *)data_end -
                (char *)data)
    );


    /*
     * Normal traffic is allowed.
     */
    return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <net/if.h>

#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#include "../include/kxflow_event.h"

static volatile std::sig_atomic_t running = 1;

static void handle_signal(int)
{
    running = 0;
}

static std::string ipv4_to_string(__u32 ip)
{
    struct in_addr addr {};
    addr.s_addr = ip;

    char buffer[INET_ADDRSTRLEN] {};

    if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr)
        return "0.0.0.0";

    return std::string(buffer);
}

static const char *protocol_name(__u8 protocol)
{
    switch (protocol)
    {
        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_UDP:
            return "UDP";

        case IPPROTO_ICMP:
            return "ICMP";

        default:
            return "OTHER";
    }
}

static const char *action_name(__u8 action)
{
    switch (action)
    {
        case XDP_ABORTED:
            return "ABORTED";

        case XDP_DROP:
            return "DROP";

        case XDP_PASS:
            return "PASS";

        case XDP_TX:
            return "TX";

        case XDP_REDIRECT:
            return "REDIRECT";

        default:
            return "UNKNOWN";
    }
}

static const char *severity_name(__u8 severity)
{
    switch (severity)
    {
        case KXFLOW_SEVERITY_INFO:
            return "INFO";

        case KXFLOW_SEVERITY_LOW:
            return "LOW";

        case KXFLOW_SEVERITY_MEDIUM:
            return "MEDIUM";

        case KXFLOW_SEVERITY_HIGH:
            return "HIGH";

        case KXFLOW_SEVERITY_CRITICAL:
            return "CRITICAL";

        default:
            return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data == nullptr || data_sz < sizeof(struct kxflow_event))
        return 0;

    const auto *event =
        static_cast<const struct kxflow_event *>(data);

    const std::string src_ip = ipv4_to_string(event->src_ip);
    const std::string dst_ip = ipv4_to_string(event->dst_ip);

    /*
     * Security alert
     */
    if (event->event_type == KXFLOW_EVENT_ALERT)
    {
        std::cout
            << "\n========================================\n"
            << "        KXFLOW SECURITY ALERT\n"
            << "========================================\n"
            << "Detection : TCP Port Scan\n"
            << "Source    : " << src_ip << "\n"
            << "Target    : " << dst_ip << "\n"
            << "Port      : " << event->dst_port << "\n"
            << "Severity  : "
            << static_cast<int>(event->severity)
            << " (" << severity_name(event->severity) << ")\n"
            << "Action    : " << action_name(event->action) << "\n"
            << "========================================\n"
            << std::flush;

        return 0;
    }

    /*
     * Normal packet telemetry
     */
    std::cout
        << "[KXFLOW EVENT] "
        << "SRC=" << src_ip
        << ":" << event->src_port
        << " DST=" << dst_ip
        << ":" << event->dst_port
        << " PROTO=" << protocol_name(event->protocol)
        << " SIZE=" << event->packet_size
        << " ACTION=" << action_name(event->action)
        << " TYPE=" << static_cast<int>(event->event_type)
        << " SEVERITY=" << static_cast<int>(event->severity)
        << " TIME=" << event->timestamp_ns
        << "\n"
        << std::flush;

    return 0;
}

static void dump_flows(struct bpf_map *flows_map)
{
    if (flows_map == nullptr)
        return;

    const int map_fd = bpf_map__fd(flows_map);

    if (map_fd < 0)
    {
        std::cerr << "Failed to get flow map FD\n";
        return;
    }

    std::cout
        << "\n========== KXFLOW FLOW TABLE ==========\n";

    struct flow_key key {};
    struct flow_key next_key {};
    struct flow_stats stats {};

    bool first = true;

    while (true)
    {
        int ret;

        if (first)
        {
            ret = bpf_map_get_next_key(
                map_fd,
                nullptr,
                &next_key
            );

            first = false;
        }
        else
        {
            ret = bpf_map_get_next_key(
                map_fd,
                &key,
                &next_key
            );
        }

        if (ret != 0)
            break;

        if (bpf_map_lookup_elem(
                map_fd,
                &next_key,
                &stats) != 0)
        {
            key = next_key;
            continue;
        }

        std::cout
            << "FLOW "
            << ipv4_to_string(next_key.src_ip)
            << ":" << next_key.src_port
            << " -> "
            << ipv4_to_string(next_key.dst_ip)
            << ":" << next_key.dst_port
            << " PROTO=" << protocol_name(next_key.protocol)
            << " PACKETS=" << stats.packet_count
            << " BYTES=" << stats.byte_count
            << " FIRST=" << stats.first_seen_ns
            << " LAST=" << stats.last_seen_ns
            << "\n";

        key = next_key;
    }

    std::cout
        << "=======================================\n";
}

int main()
{
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    const char *bpf_object_path =
        "/home/harish/KXFlow/build/xdp_main.bpf.o";

    const char *ifname = "enp0s3";

    const int ifindex = if_nametoindex(ifname);

    if (ifindex == 0)
    {
        std::cerr
            << "Failed to find interface: "
            << ifname << "\n";

        return 1;
    }

    std::cout
        << "========================================\n"
        << "        KXFlow Detection Engine\n"
        << "========================================\n"
        << "BPF object : "
        << bpf_object_path << "\n"
        << "Interface  : "
        << ifname << "\n"
        << "Detection  : TCP port scan\n"
        << "Threshold  : 10 unique TCP ports / 10 seconds\n"
        << "Enforcement: PASS / DROP\n\n";

    struct bpf_object *obj =
        bpf_object__open_file(
            bpf_object_path,
            nullptr
        );

    if (libbpf_get_error(obj))
    {
        std::cerr
            << "Failed to open BPF object: "
            << bpf_object_path << "\n";

        return 1;
    }

    if (bpf_object__load(obj) != 0)
    {
        std::cerr
            << "Failed to load BPF object\n";

        bpf_object__close(obj);

        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(
            obj,
            "kxflow_xdp"
        );

    if (prog == nullptr)
    {
        std::cerr
            << "Failed to find XDP program: kxflow_xdp\n";

        bpf_object__close(obj);

        return 1;
    }

    struct bpf_link *link =
        bpf_program__attach_xdp(
            prog,
            ifindex
        );

    if (libbpf_get_error(link))
    {
        std::cerr
            << "Failed to attach XDP program to "
            << ifname << "\n";

        bpf_object__close(obj);

        return 1;
    }

    std::cout
        << "XDP attached to: "
        << ifname << "\n";

    struct bpf_map *events_map =
        bpf_object__find_map_by_name(
            obj,
            "events"
        );

    if (events_map == nullptr)
    {
        std::cerr
            << "Failed to find RingBuf map: events\n";

        bpf_link__destroy(link);
        bpf_object__close(obj);

        return 1;
    }

    const int events_fd =
        bpf_map__fd(events_map);

    if (events_fd < 0)
    {
        std::cerr
            << "Failed to get RingBuf map FD\n";

        bpf_link__destroy(link);
        bpf_object__close(obj);

        return 1;
    }

    struct ring_buffer *ringbuf =
        ring_buffer__new(
            events_fd,
            handle_event,
            nullptr,
            nullptr
        );

    if (ringbuf == nullptr)
    {
        std::cerr
            << "Failed to create RingBuf\n";

        bpf_link__destroy(link);
        bpf_object__close(obj);

        return 1;
    }

    std::cout
        << "RingBuf consumer started...\n\n";

    while (running)
    {
        const int ret =
            ring_buffer__poll(
                ringbuf,
                100
            );

        if (ret < 0)
        {
            if (ret == -EINTR)
                continue;

            std::cerr
                << "RingBuf polling failed: "
                << ret << "\n";

            break;
        }
    }

    std::cout
        << "\nStopping KXFlow consumer...\n";

    struct bpf_map *flows_map =
        bpf_object__find_map_by_name(
            obj,
            "flows"
        );

    dump_flows(flows_map);

    ring_buffer__free(ringbuf);

    bpf_link__destroy(link);

    bpf_object__close(obj);

    std::cout
        << "KXFlow consumer stopped.\n";

    return 0;
}

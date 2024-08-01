#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

struct packet_info {
    __u64 pkt_len;
    __u64 pkt_type;
};

SEC("classifier/egress/drop")
int egress_drop(struct __sk_buff *skb)
{
    struct packet_info pkt = {};
    pkt.pkt_len = skb->len;
    pkt.pkt_type = 0; // 0 for egress

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &pkt, sizeof(pkt));

    return TC_ACT_SHOT;
}

SEC("classifier/ingress/drop")
int ingress_drop(struct __sk_buff *skb)
{
    struct packet_info pkt = {};
    pkt.pkt_len = skb->len;
    pkt.pkt_type = 1; // 1 for ingress

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &pkt, sizeof(pkt));

    return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";

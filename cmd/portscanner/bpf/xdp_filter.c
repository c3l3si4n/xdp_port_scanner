#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// IMPORTANT: This is the hardcoded source port for filtering.
// If you change the -srcport flag in the Go program, you MUST
// change this value to match and recompile this eBPF program.
#define FILTER_PORT 54321

/*
 * This is the XSK map, which is used to redirect packets to a userspace
 * socket. The key is the queue ID, and the value is the socket's file
 * descriptor.
 */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1); // Only using queue 0
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_port_filter(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;

	// Basic bounds check
	if ((void *)eth + sizeof(*eth) > data_end) {
		return XDP_PASS;
	}

	// We only care about IPv4 packets
	if (eth->h_proto != __bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	struct iphdr *ip = (void *)eth + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end) {
		return XDP_PASS;
	}

	// We only care about TCP packets
	if (ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}

	struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
	if ((void *)tcp + sizeof(*tcp) > data_end) {
		return XDP_PASS;
	}

	// Filter for packets destined to our source port
	if (tcp->dest == __bpf_htons(FILTER_PORT)) {
		return bpf_redirect_map(&xsks_map, 0, 0);
	}

	// Otherwise, let the packet continue to the kernel's network stack
	return XDP_PASS;
}

// Basic license requirement for eBPF programs.
char _license[] SEC("license") = "GPL"; 
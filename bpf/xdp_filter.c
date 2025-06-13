#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/*
 * This is the XSK map, which is used to redirect packets to a userspace
 * socket. The key is the queue ID, and the value is the socket's file
 * descriptor.
 */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
} xsks_map SEC(".maps");

/*
 * This variable will be set from userspace. It holds the TCP port number
 * that we want to filter for. The `volatile` and `const` keywords are
 * hints to the compiler to prevent it from optimizing away this variable,
 * allowing it to be modified before the program is loaded.
 */
volatile const __u16 filter_port = 0;

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

	// If the destination port matches our filter, redirect to the socket
	if (tcp->dest == __bpf_htons(filter_port)) {
		return bpf_redirect_map(&xsks_map, 0, 0);
	}

	// Otherwise, let the packet continue to the kernel's network stack
	return XDP_PASS;
}

// Basic license requirement for eBPF programs.
char _license[] SEC("license") = "GPL"; 
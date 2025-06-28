#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// --- IMPORTANT ---
// This range must match the source ports used by the Go scanner.
// Example: -srcport 54321 -num-queues 4 uses ports 54321, 54322, 54323, 54324.
#define FILTER_PORT_START 54321
#define FILTER_PORT_END   54324

// --- Map Definitions ---
// These use the modern libbpf format.
// We size them to be flexible, even though we only redirect to queue 0.

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 64); // Flexible size for multiple queues
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 64);
} qidconf_map SEC(".maps");

// --- XDP Program ---

SEC("xdp")
int xdp_port_filter(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	__u16 dest_port;

	// Bounds check for Ethernet header
	if ((void *)eth + sizeof(*eth) > data_end) {
		return XDP_PASS;
	}

	// Filter for IPv4 packets
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	// Bounds check for IP header
	ip = (void *)eth + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end) {
		return XDP_PASS;
	}

	// Filter for TCP packets
	if (ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}

	// Bounds check for TCP header
	tcp = (void *)ip + (ip->ihl * 4);
	if ((void *)tcp + sizeof(*tcp) > data_end) {
		return XDP_PASS;
	}

	// --- LOGIC CHANGE IS HERE ---
	// Convert the packet's destination port to host byte order for comparison.
	dest_port = bpf_ntohs(tcp->dest);

	// Check if the destination port is within our scanner's reply port range.
	if (dest_port >= FILTER_PORT_START && dest_port <= FILTER_PORT_END) {
		// If it's a reply to our scanner, redirect it to the AF_XDP socket
		// that is registered on QUEUE 0.
		return bpf_redirect_map(&xsks_map, 0, 0);
	}

	// Otherwise, let the packet continue to the kernel's network stack.
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
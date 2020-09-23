/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
//#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

struct hdr_cursor {
	void *pos;
};

static __always_inline int parse_eth_header(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	if (nh->pos + hdrsize <= data_end) {
	  nh->pos += hdrsize;
	  *ethhdr = eth;
	  return 0;
  }

  return -1;
}

static __always_inline int parse_ip_header(struct hdr_cursor *nh, void *data_end, struct iphdr **ip_header) {
  struct iphdr *ip = nh->pos;
  int hdrsize = sizeof(*ip);
  if(nh->pos + hdrsize <= data_end) {
    nh->pos += hdrsize;
    *ip_header = ip;
    return 0;
  }

  return -1;
}

static __always_inline int parse_tcp_header(struct hdr_cursor *nh, void *data_end, struct tcphdr **tcp_header) {
  struct tcphdr *tcp = nh->pos;
  int hdrsize = sizeof(*tcp);
  if(nh->pos + hdrsize <= data_end) {
    nh->pos += hdrsize;
    *tcp_header = tcp;
    return 0;
  }

  return -1;
}

static __always_inline int parse_headers(struct hdr_cursor *nh, void *data_end, struct ethhdr **eth_header, struct iphdr **ip_header, struct tcphdr **tcp_header) {
  return parse_eth_header(nh, data_end, eth_header) || parse_ip_header(nh, data_end, ip_header) || parse_tcp_header(nh, data_end, tcp_header);
}

static __always_inline int is_ipv4(struct ethhdr *eth_header) {
  return eth_header->h_proto == bpf_htons(ETH_P_IP);
}

static __always_inline int is_tcp(struct iphdr *ip_header) {
  return ip_header->protocol == IPPROTO_TCP;
}

static __always_inline __u32 hash_five_tuple(struct iphdr *ip_header, struct tcphdr *tcp_header, int reverse) {
  __u32 saddr;
  __u32 daddr;
  __u32 srcport;
  __u32 dstport;
  __u32 protocol = (__u32)ip_header->protocol;

	if (reverse) {
		saddr = bpf_htons(ip_header->daddr);
		daddr = bpf_htons(ip_header->saddr);
		srcport = (__u32)bpf_htons(tcp_header->dest);
		dstport = (__u32)bpf_htons(tcp_header->source);
	}
	else {
		saddr = bpf_htons(ip_header->saddr);
		daddr = bpf_htons(ip_header->daddr);
		srcport = (__u32)bpf_htons(tcp_header->source);
		dstport = (__u32)bpf_htons(tcp_header->dest);
	}

	// See https://play.golang.org/p/oluzKYVKpeR for example implementation of a 5-tuple hash
	return (saddr * 59) ^ daddr ^ (srcport << 16) ^ dstport ^ protocol;
}

static __always_inline __u32 hash_five_tuple_lan_ingress(struct iphdr *ip_header, struct tcphdr *tcp_header) {
	return hash_five_tuple(ip_header, tcp_header, 0);
}

static __always_inline __u32 hash_five_tuple_wan_ingress(struct iphdr *ip_header, struct tcphdr *tcp_header) {
	return hash_five_tuple(ip_header, tcp_header, 1);
}

static __always_inline int isLocalInterfaceMacAddr(struct bpf_fib_lookup *local_fib_params, struct ethhdr *eth_header) {
	return (__u64)*(local_fib_params->smac) == (__u64)*(eth_header->h_dest);
}

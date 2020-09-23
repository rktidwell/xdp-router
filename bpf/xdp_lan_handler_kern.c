
/* SPDX-License-Identifier: Apache-2.0 */
#include "xdp_common.h"

SEC("xdp_lan_handler")
int  handle_lan_xdp(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
  struct ethhdr *eth_header;
  struct iphdr *ip_header;
  struct tcphdr *tcp_header;
  struct hdr_cursor nh;
  struct bpf_fib_lookup ingress_fib_params;
  struct bpf_fib_lookup fib_params;
  __builtin_memset(&ingress_fib_params, 0, sizeof(ingress_fib_params));
  __builtin_memset(&fib_params, 0, sizeof(fib_params));

  // perform a bpf_fib_lookup() to find the MAC and IP addresses of the ingress interface
  ingress_fib_params.family = 2; //AF_INET
  ingress_fib_params.ifindex = ctx->ingress_ifindex;
  int rc = bpf_fib_lookup(ctx, &ingress_fib_params, sizeof(ingress_fib_params), BPF_FIB_LOOKUP_DIRECT);

  // this should succeed, but if for some reason we encounter an error from bpf_fib_lookup(), pass up the stack
  if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
    bpf_printk("bpf_fib_lookup() returned %d, passing up the stack", rc);
    return XDP_PASS;
  }

  nh.pos = data;
  if (parse_headers(&nh, data_end, &eth_header, &ip_header, &tcp_header) == 0) {
    if (isLocalInterfaceMacAddr(&ingress_fib_params, eth_header) && is_ipv4(eth_header) && is_tcp(ip_header)) {
      // Compute a 5-tuple hash, we'll use this as the key into our conntrack map
			__u32 hash = hash_five_tuple_lan_ingress(ip_header, tcp_header);
      // Log the 5-tuple hash for fun
      bpf_printk("5-Tuple Hash: %u", hash);
    }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

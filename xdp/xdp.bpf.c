// SPDX-License-Identifier: GPL-2.0
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

/*
 * XDP program that dumps packet size and TCP data size
 */

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/*
 *  IEEE 802.3 Ethernet magic constants, you can fins them in the
 *  kernel source at linux/include/uapi/linux/if_ether.h
 */
#define ETH_P_IP   0x0800    /* Internet Protocol packet */
#define ETH_P_IPV6 0x86DD    /* IPv6 over bluebook       */

/*
 *  Some IANA protocol numbers
 */
#define ICMP_PROTO_NUMBER 0x01
#define TCP_PROTO_NUMBER  0x06
#define UDP_PROTO_NUMBER  0x11
#define IPV6_PROTO_NUMBER 0x29  /* IPv6 encapsulation */
// ...

#define NETWORK_INTERFACE_MTU 1500  /* TODO: this depends on the machine and should be generated */
#define MAX_TCP_IPV4_DATA_SIZE (NETWORK_INTERFACE_MTU - sizeof(struct tcphdr) - sizeof(struct iphdr))

/* Attempts to parse the ethernet frame. This function simply walks
 * through the nested layers of payloads (for example, ethernet -> ip
 * -> tcp -> http) and populates the fields in _out_. */
static __always_inline int xdp_parse_frame(struct xdp_md *ctx)
{
  void *data_end = (void*)(long)ctx->data_end;
  void *data     = (void*)(long)ctx->data;

  bpf_printk("packet size is %d", data_end - data);

  struct ethhdr *eth = data;

  if ((void*)(eth+1) > data_end)
    return 0;

  if (eth->h_proto == bpf_ntohs(ETH_P_IP)) {
    struct iphdr *ip = (void*)(eth + 1);

    if ((void*)(ip + 1) > data_end)
      return 0;

    if (ip->protocol != TCP_PROTO_NUMBER) // Only interested in TCP
      return 0;

    struct tcphdr *tcp = (void*)ip + ip->ihl * 4;

    if ((void*)(tcp + 1) > data_end)
      return 0;

    int tcp_hdr_len = tcp->doff * 4;
    char* tcp_payload = (void*)tcp + tcp_hdr_len;
    int tcp_data_offset = (void*)tcp_payload - data;

    __u32 last = 0;
    __u8 byte;
    for (size_t i = 0; i < MAX_TCP_IPV4_DATA_SIZE; ++i)
    {
        // Do something...
    }

    bpf_printk("Found TCP payload of size %d\n", data_end - (void*)tcp_payload);
    return 1;
  } else if (eth->h_proto == bpf_ntohs(ETH_P_IPV6)) { // IPv6
    return -1; // Not supported yet
  }

  return 0; // We are not interested, thanks
}

/*
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	// Below access go through struct xdp_rxq_info
	__u32 ingress_ifindex; // rxq->dev->ifindex
	__u32 rx_queue_index;  // rxq->queue_index

	__u32 egress_ifindex;  // txq->dev->ifindex
};
*/
SEC("xdp")
int handle_xdp(struct xdp_md *ctx)
{
    if (xdp_parse_frame(ctx) < 0)
        bpf_printk("Error parsing frame\n");

    return XDP_PASS;
}

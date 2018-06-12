#ifndef __L4_H
#define __L4_H

#include <iproute2/bpf_api.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "./common.h"

static inline int __inline__ l4_tcp_room(void)
{
	return sizeof(struct ethhdr) + sizeof(struct iphdr) +
	       sizeof(struct tcphdr);
}

/**
 * Takes a sk_buff struct and prints to the trace utility
 * what source and destination ports are set in the TCP
 * package.
 */
static inline int __inline__ l4_show_ports(
  struct __sk_buff* __attribute__((unused)) skb,
  void* data,
  void* data_end,
  __u32 off)
{
	struct iphdr*  ip;
	struct tcphdr* tcp;

	/**
	 * Being the `ip` header the very next thing after the
	 * ethernet header, we can just jump to that place from
	 * the offset set in the parameters.
	 */
	ip = data + off;
	off += sizeof(struct iphdr);

	/**
	 * Check whether the underlying data storage has enough
	 * space filled to container at least the ip header in its
	 * full size.
	 */
	if ((void*)ip + sizeof(struct iphdr) > data_end) {
		printk("not enough data for proper iphdr struct\n");
		return TC_ACT_UNSPEC;
	}

	/**
	 * ihl stands for Internet Header Length, which is the length
	 * of the ip header in 32-bit words.
	 *
	 * Given that the size of `struct iphdr` is 20 octets, we expect
	 * the IHL to be set to 5:
	 * > 5 * 32 == 160
	 * > 20 * 8 == 160
	 */
	if (ip->ihl != 5) {
		printk(
		  "ip->ihl must equal to 5 to match the internal iphdr size\n");
		return TC_ACT_UNSPEC;
	}

	if (ip->protocol != IPPROTO_TCP) {
		printk("not tcp\n");
		return TC_ACT_UNSPEC;
	}

	tcp = data + off;
	if ((void*)tcp + sizeof(struct tcphdr) > data_end) {
		printk("not enough data for proper tcphdr struct\n");
		return TC_ACT_UNSPEC;
	}

	printk("src=%u:%u\n", htonl(ip->saddr), htons(tcp->source));
	printk("dst=%u:%u\n", htonl(ip->daddr), htons(tcp->dest));

	return -1;
}

#endif

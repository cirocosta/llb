#ifndef __L4_H
#define __L4_H

#include <iproute2/bpf_api.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "./common.h"

static inline int __inline__ l4_show_ports(struct __sk_buff* skb, int nh_off)
{
	__u16 dport;
	__u16 sport;
	__u8  ip_proto;
	__u8  ip_vl;

	ip_proto = load_byte(skb, nh_off + offsetof(struct iphdr, protocol));
	if (ip_proto != IPPROTO_TCP)
		return 0;

	ip_vl = load_byte(skb, nh_off);
	if (ip_vl == 0x45) {
		nh_off += sizeof(struct iphdr);
	} else {
		nh_off += (ip_vl & 0xF) << 2;
	}

	dport = load_half(skb, nh_off + offsetof(struct tcphdr, dest));
	sport = load_half(skb, nh_off + offsetof(struct tcphdr, source));
	printk("src=%u,dst=%u\n", sport, dport);

	return -1;
}

#endif

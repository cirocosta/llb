#ifndef __L4_H
#define __L4_H

#include <iproute2/bpf_api.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "./common.h"

static inline int __inline__ l4_show_ports(struct __sk_buff* skb, int nh_off)
{
	int   ret = 0;
	__u16 dport;
	__u16 sport;
	__u8  ip_proto;
	__u8  ip_vl;

	ret = skb_load_bytes(skb,
	                     nh_off + offsetof(struct iphdr, protocol),
	                     &ip_proto,
	                     sizeof(__u8));
	if (ret < 1) {
		printk("errored loading bytes (ip_proto)\n");
		return ret;
	}

	if (ip_proto != IPPROTO_TCP) {
		printk("ip_proto is not IPPROTO_TCP\n");
		return 0;
	}

	ret = skb_load_bytes(skb, nh_off, &ip_vl, sizeof ip_vl);
	if (ret < 1) {
		printk("errored loading bytes (ip_vl)\n");
		return ret;
	}

	if (ip_vl == 0x45) {
		nh_off += sizeof(struct iphdr);
	} else {
		nh_off += (ip_vl & 0xF) << 2;
	}

	ret = skb_load_bytes(
	  skb, nh_off + offsetof(struct tcphdr, dest), &dport, sizeof dport);
	if (ret < 1) {
		printk("errored loading bytes (dport)\n");
		return ret;
	}

	ret = skb_load_bytes(
	  skb, nh_off + offsetof(struct tcphdr, source), &sport, sizeof sport);
	if (ret < 1) {
		printk("errored loading bytes (sport)\n");
		return ret;
	}

	printk("src=%u,dst=%u\n", sport, dport);

	return -1;
}

#endif

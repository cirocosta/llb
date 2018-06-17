/**
 * Each of these classifiers take a packet in its parsed form
 * (sk_buff) and then reads information contained in them by
 * jumping to the right places in the data buffer according to
 * each layer's header size.
 *
 * Being `sk_buff` a generic structure for packets, there we
 * have information from three layers in the OSI model:
 * - link (l2 - ethernet);
 * - network (l3 - ipv4/ipv6); and
 * - transport (l4 - tcp/udp).
 *
 * The classifiers are meant to be loaded through the `tc` command
 * to a netdevice which should have a `clsact` qdisc (queueing
 * discipline) so we can attach the corresponding ingress and
 * egress classifiers to the right traffic paths.
 *
 * Once packets start traversing the device, the corresponding program
 * gets executed.
 *
 * The return value (int) of the program corresponds to the tc
 * action veridict (see <linux/pkt_cls.h>).
 *
 * - TC_ACT_UNSPEC can be used as a way of telling the kernel to
 *   continue with the skb without additional side-effects;
 *
 * - TC_ACT_SHOT, for dropping; and
 *
 * - TC_ACT_REDIRECT for forwarding.
 */

#include <linux/if_ether.h>

#include "./l3.h"
#include "./l4.h"
#include "./maps.h"

__section("ingress") int cls_ingress(struct __sk_buff* skb)
{
	int   ret      = 0;
	void* data     = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	if (l3_is_ip(skb) & LLB_ERR) {
		return TC_ACT_UNSPEC;
	}

	if (l4_is_tcp_packet(data, data_end) & LLB_ERR) {
		return TC_ACT_UNSPEC;
	}

	connection_t conn = { .src = { 0 }, .dst = { 0 } };
	ret               = l4_extract_endpoints(data, data_end, &conn);
	if (ret & LLB_ERR) {
		return TC_ACT_UNSPEC;
	}

	connection_t dnat_key = {
		.src = conn.dst,
		.dst = conn.src,
	};

	connection_t* existing_connection =
	  map_lookup_elem(&llb_h_dnat, &dnat_key);
	if (!existing_connection) {
		return TC_ACT_UNSPEC;
	}

	return TC_ACT_UNSPEC;
}

__section("egress") int cls_egress(struct __sk_buff* __attribute__((unused))
                                   skb)
{
	int   ret      = 0;
	void* data     = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	if (l3_is_ip(skb) & LLB_ERR) {
		return TC_ACT_UNSPEC;
	}

	if (l4_is_tcp_packet(data, data_end) & LLB_ERR) {
		return TC_ACT_UNSPEC;
	}

	connection_t conn = { .src = { 0 }, .dst = { 0 } };
	ret               = l4_extract_endpoints(data, data_end, &conn);
	if (ret & LLB_ERR) {
		return TC_ACT_UNSPEC;
	}

	if (conn.dst.port != LLB_FRONTEND_PORT) {
		return TC_ACT_UNSPEC;
	}

	printk("[egr] src(addr=%u,port=%u)\n", conn.src.address, conn.src.port);
	printk("[egr] dst(addr=%u,port=%u)\n", conn.dst.address, conn.dst.port);

	__u8 machine_ip[4]    = { 10, 0, 2, 15 };
	__u8 destintion_ip[4] = { 172, 17, 0, 3 };

	connection_t new_conn = { { 0 }, { 0 } };
	new_conn.src.address  = l3_bytes_to_le32(machine_ip);
	new_conn.src.port     = conn.src.port;
	new_conn.dst.address  = l3_bytes_to_le32(destintion_ip);
	new_conn.dst.port     = conn.dst.port;

	printk("[egr] new_src(addr=%u,port=%u)\n",
	       new_conn.src.address,
	       new_conn.src.port);
	printk("[egr] new_dst(addr=%u,port=%u)\n",
	       new_conn.dst.address,
	       new_conn.dst.port);

	ret = map_update_elem(&llb_h_dnat, &conn, &new_conn, BPF_ANY);
	if (ret != 0) {
		return TC_ACT_UNSPEC;
	}

	ret = l4_replace_skb_addr(skb,
	                          &conn.dst.address,
	                          &new_conn.dst.address,
	                          offsetof(struct iphdr, daddr));
	if (ret & LLB_ERR) {
		printk("[egr] failed to replace skb destination addr");
		return TC_ACT_UNSPEC;
	}

	ret = l4_replace_skb_addr(skb,
	                          &conn.src.address,
	                          &new_conn.src.address,
	                          offsetof(struct iphdr, saddr));
	if (ret & LLB_ERR) {
		printk("[egr] failed to replace skb source addr");
		return TC_ACT_UNSPEC;
	}

	return ret;
};

BPF_LICENSE("GPL");

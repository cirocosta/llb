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
	void* data     = (void*)(long)skb->data;
	void* data_end = (void*)(long)skb->data_end;

	if (l3_is_ip(skb) & LLB_ERR) {
		return TC_ACT_UNSPEC;
	}

	if (l4_is_tcp_packet(data, data_end) & LLB_ERR) {
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

	printk("src(addr=%u,port=%u)\n", conn.src.address, conn.src.port);
	printk("dst(addr=%u,port=%u)\n", conn.dst.address, conn.dst.port);

	if (conn.dst.port != LLB_FRONTEND_PORT) {
		printk("packet not destinet to frontend port\n");
		return TC_ACT_UNSPEC;
	}

	connection_t* existing_connection = map_lookup_elem(&llb_h_dnat, &conn);
	if (existing_connection) {
		printk("connection already known\n");
		return TC_ACT_UNSPEC;
	}

	// pick a backend

	__u32       key              = 1;
	endpoint_t* selected_backend = map_lookup_elem(&llb_h_bnx, &key);
	if (!selected_backend) {
		printk("no backend selected\n");
		return TC_ACT_UNSPEC;
	}

	printk("backend selected: addr=%u,port=%u\n",
	       selected_backend->address,
	       selected_backend->port);

	// route to that backend and keep track
	// of the traffic that should go towards
	// such backend.
	connection_t new_conn = {
		.src =
		  {
		    .address =
		      (172 << 24 | 17 << 16 | 0 << 8 | 1), // our machine ip
		    .port = conn.src.port,
		  },
		.dst =
		  {
		    .address = selected_backend->address,
		    .port    = conn.src.port,
		  },
	};

	map_update_elem(&llb_h_dnat, &conn, &new_conn, 0);

	// keep track of the traffic that will come
	// back from such connection.
	connection_t snat_conn_key = {
		.src = new_conn.dst,
		.dst = new_conn.src,
	};

	connection_t snat_conn_value = {
		.src = conn.dst,
		.dst = conn.src,
	};

	map_update_elem(&llb_h_snat, &snat_conn_key, &snat_conn_value, 0);

	return ret;
};

BPF_LICENSE("GPL");

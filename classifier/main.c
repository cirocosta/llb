#include <linux/if_ether.h>

#include "./l4.h"
#include "./lb.h"

#define LLB_BACKENDS_ARR_MAX_ELEM 256
#define LLB_CONNECTIONS_MAP_MAX_ELEM 256
#define LLB_FRONTEND_PORT 8080

/**
 * llb_backends_arr contains an array of all the backends that
 * have been configured for load-balancing.
 *
 * Given a scheduling policy, llb should pick one backend
 * from this list and submit the packets for it.
 *
 * This array is meant to be updated (and initialized) from
 * userspace only.
 */
struct bpf_elf_map __section_maps llb_h_bnx = {
	.type       = BPF_MAP_TYPE_HASH,
	.size_key   = sizeof(__u32),
	.size_value = sizeof(backend_t),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem   = LLB_BACKENDS_ARR_MAX_ELEM,
};

/**
 * llb_connections_map introduces statefulness into the packet
 * forwarding by keeping track of which backend has been chosen
 * for a given packet such that we keep sending packets that
 * correspond to a connection to a particular backend.
 */
struct bpf_elf_map __section_maps llb_h_cnx = {
	.type       = BPF_MAP_TYPE_HASH,
	.size_key   = sizeof(connection_key_t),
	.size_value = sizeof(backend_t),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem   = LLB_CONNECTIONS_MAP_MAX_ELEM,
};

/**
 * This classifier takes a packet in its already parsed form
 * (sk_buff) and then reads information contained in it if
 * it's a TCP packet.
 *
 * Being `sk_buff` a generic structure for packets, there we
 * have information from three layers in the OSI model:
 * - link (l2 - ethernet);
 * - network (l3 - ipv4/ipv6); and
 * - transport (l4 - tcp/udp).
 *
 * It's meant to be loaded through the `tc` command to a netdevice
 * which should have a `clsact` qdisc (queueing discipline) so we
 * can attach the classifier to either the ingress or egress hooks.
 *
 * Once packets start traversing the device, the program gets
 * executed.
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
__section("classifier") int cls_main(struct __sk_buff* skb)
{
	int            ret      = 0;
	void*          data     = (void*)(long)skb->data;
	void*          data_end = (void*)(long)skb->data_end;
	struct ethhdr* eth;
	__u32          off;

	off = sizeof(struct ethhdr);
	if (data + off > data_end) {
		printk("packet w/out space for eth struct\n");
		return TC_ACT_UNSPEC;
	}

	eth = data;
	if (eth->h_proto != __constant_htons(ETH_P_IP)) {
		printk("not an internet protocol packet\n");
		return TC_ACT_UNSPEC;
	}

	/**
	 * `skb->protocol` [1] corresponds to the packet protocol as seen
	 * from the driver.
	 *
	 * If we're seeing a packet that is not of the type that we expect,
	 * then just leave it to other pieces of the stack. Otherwise,
	 * let's process it ourselves.
	 *
	 *
	 *      ETH_P_IP: Internet Protocol Packet [2]
	 *
	 *      [1]:
	 * https://elixir.bootlin.com/linux/v4.15/source/include/linux/skbuff.h#L618
	 *
	 *      [2]:
	 * https://elixir.bootlin.com/linux/v4.15/source/include/uapi/linux/if_ether.h#L51
	 */
	// if (skb->protocol != __constant_htons(ETH_P_IP)) {
	// 	return TC_ACT_UNSPEC;
	// }

	ret = l4_show_ports(skb, data, data_end, off);
	return ret;
}

BPF_LICENSE("GPL");

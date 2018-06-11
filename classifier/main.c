#include "./l4.h"
#include <linux/if_ether.h>

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

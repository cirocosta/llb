#include "./l4.h"

__section("classifier") int cls_main(struct __sk_buff* skb)
{
	int ret    = 0;
	int nh_off = ETH_HLEN;

	if (skb->protocol == __constant_htons(ETH_P_IP)) {
		ret = l4_show_ports(skb, nh_off);
	}

	return ret;
}

BPF_LICENSE("GPL");

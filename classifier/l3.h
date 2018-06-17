#ifndef __LLB_CLASSIFIER_L3_H
#define __LLB_CLASSIFIER_L3_H

#include "./common.h"
#include <iproute2/bpf_api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define LLB_L3_OFF sizeof(struct ethhdr)
#define LLB_L3_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))

/**
 * Verifies whether the given skb corresponds to
 * an IPV4 packet.
 */
static inline int __attribute__((always_inline)) l3_is_ip(struct __sk_buff* skb)
{
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
	 *
	 * Given that the field is not reserver to a specific prog type,
	 * we have access to it.
	 */
	if (skb->protocol != htons(ETH_P_IP)) {
		return LLB_ERR;
	}

	return LLB_OK;
}

static inline void
l3_extract_address_le(__le32 addr, __u8 ip_addr[4])
{
	ip_addr[0] = addr & ((1 << 8) - 1);
	ip_addr[1] = (addr >> 8) & ((1 << 8) - 1);
	ip_addr[2] = (addr >> 16) & ((1 << 8) - 1);
	ip_addr[3] = (addr >> 24);
}

static inline void
l3_extract_address_be(__be32 addr, __u8 ip_addr[4])
{
	ip_addr[0] = (addr >> 24);
	ip_addr[1] = (addr >> 16) & ((1 << 8) - 1);
	ip_addr[2] = (addr >> 8) & ((1 << 8) - 1);
	ip_addr[3] = addr & ((1 << 8) - 1);
}

#endif

#ifndef __L4_H
#define __L4_H

#include <iproute2/bpf_api.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "./common.h"
#include "./l3.h"

#define LLB_L4_OFF LLB_L3_OFF + sizeof(struct iphdr)
#define LLB_L4_CSUM_OFF (LLB_L4_OFF + offsetof(struct tcphdr, check))

// Replaces the address information (L3) of a given L4 packet by modifying
// its SKB data an recalculating its checksums (at both L3 and L4).
//
// Given that there are two possible addresses to be modified, the right
// offset must be provided to `iphdr_offset`:
// - source:      offsetof(struct iphdr, saddr);
// - destination: offsetof(struct iphdr, daddr);
static inline int __inline__ l4_replace_skb_addr(struct __sk_buff* skb,
                                                 __u32*            addr_before,
                                                 __u32*            addr_after,
                                                 __u32             iphdr_offset)
{
	int ret = 0;

	// Replace the packet's address with the new one.
	ret =
	  skb_store_bytes(skb,
	                  LLB_L3_OFF + iphdr_offset, // where in `skb->data`
	                  addr_after, // pointer to where to copy `n` bytes from
	                  4,          // `n` bytes to copy
	                  0 // flags: 0th bit: if set -> recompute csum
	  );
	if (ret < 0) {
		printk("couldn't store new addr bytes in skb\n");
		return LLB_ERR;
	}

	// Replace the L4 checksum as the pseudo-headers (that keep track
	// of the underlying l3 data) have changed.
	ret = l4_csum_replace(
	  skb,
	  LLB_L4_CSUM_OFF, // where in `skb->data` the tcp checksum lives
	  *addr_before,    // address before
	  *addr_after,     // address after
	  4 | (1 << 4)); // the first 3 bits indicate the size of the addr; the
	                 // 4th, whether it's a pseudo header
	if (ret != 0) {
		printk("failed to replace l4 csum\n");
		return LLB_ERR;
	}

	// Replace the L3 checksum as the L3 information changed.
	// `l3_csum_replace` essentially takes the same arguments as the l4
	// counterpart.
	ret =
	  l3_csum_replace(skb, LLB_L3_CSUM_OFF, *addr_before, *addr_after, 4);
	if (ret != 0) {
		printk("failed to replace l3 csum\n");
		return LLB_ERR;
	}

	return LLB_OK;
}

/**
 * Verifies whether the packet as described by its data is a
 * tcp packet or not.
 */
static inline int __inline__ l4_is_tcp_packet(void* data, void* data_end)
{
	struct iphdr*  ip;
	struct tcphdr* tcp;
	__u32          off;

	/**
	 * As the header that comes right before the IP header is
	 * the ethrnet header, capture it.
	 */
	off = sizeof(struct ethhdr);

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
		return LLB_ERR;
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
		return LLB_ERR;
	}

	/**
	 * Check if it's TCP - not handling UDP for now.
	 */
	if (ip->protocol != IPPROTO_TCP) {
		printk("not tcp\n");
		return LLB_ERR;
	}

	/**
	 * Verifiy whether the whole header struct can exist in the
	 * packet.
	 */
	tcp = data + off;
	if ((void*)tcp + sizeof(struct tcphdr) > data_end) {
		printk("not enough data for proper tcphdr struct\n");
		return LLB_ERR;
	}

	return LLB_OK;
}

/**
 * Takes a skb data range extracts the corresponding L4 endpoints
 * from it.
 *
 * Returns:
 * - LLB_NOT_L4 if not tcp or udp; and
 * - LLB_ERR on error.
 */
static inline int __inline__ l4_extract_endpoints(void*         data,
                                                  void*         data_end,
                                                  connection_t* conn)
{
	struct iphdr*  ip  = data + sizeof(struct ethhdr);
	struct tcphdr* tcp = (void*)ip + sizeof(struct iphdr);

	/**
	 * Verifiy whether the whole header struct can exist in the
	 * packet.
	 */
	if ((void*)tcp + sizeof(struct tcphdr) > data_end) {
		printk("not enough data for proper tcphdr struct\n");
		return LLB_ERR;
	}

	/**
	 * Fill source and dest with the values all in network byte
	 * order.
	 */
	conn->src.address = htonl(ip->saddr);
	conn->dst.address = htonl(ip->daddr);
	conn->src.port    = htons(tcp->source);
	conn->dst.port    = htons(tcp->dest);

	return LLB_OK;
}

#endif

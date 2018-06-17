#ifndef __L4_H
#define __L4_H

#include <iproute2/bpf_api.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "./common.h"

/**
 * endpoint_t represents a L4 endpoint that acts
 * either as a client or a server in a connection.
 */
typedef struct endpoint {
	// The IPV4 address of the source connection.
	__u32 address;
	// The port of the source connection.
	__u16 port;
} endpoint_t;

/**
 * connection_t represents a full L4 connection that
 * has information about a givne source and a destination.
 */
typedef struct connection {
	endpoint_t src;
	endpoint_t dst;
} connection_t;

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
		return LLB_NOT_L4;
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
		return LLB_NOT_L4;
	}

	/**
	 * Check if it's TCP - not handling UDP for now.
	 */
	if (ip->protocol != IPPROTO_TCP) {
		printk("not tcp\n");
		return LLB_NOT_L4;
	}

	/**
	 * Verifiy whether the whole header struct can exist in the
	 * packet.
	 */
	tcp = data + off;
	if ((void*)tcp + sizeof(struct tcphdr) > data_end) {
		printk("not enough data for proper tcphdr struct\n");
		return LLB_MALFORMED_L4;
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

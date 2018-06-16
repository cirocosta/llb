#ifndef __LLB_BPF_IP_H
#define __LLB_BPF_IP_H

#include <linux/types.h>

static inline void
ip_extract_address_le(__le32 addr, __u8 ip_addr[4])
{
	ip_addr[0] = addr & ((1 << 8) - 1);
	ip_addr[1] = (addr >> 8) & ((1 << 8) - 1);
	ip_addr[2] = (addr >> 16) & ((1 << 8) - 1);
	ip_addr[3] = (addr >> 24);
}

static inline void
ip_extract_address_be(__be32 addr, __u8 ip_addr[4])
{
	ip_addr[0] = (addr >> 24);
	ip_addr[1] = (addr >> 16) & ((1 << 8) - 1);
	ip_addr[2] = (addr >> 8) & ((1 << 8) - 1);
	ip_addr[3] = addr & ((1 << 8) - 1);
}

#endif

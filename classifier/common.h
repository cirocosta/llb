#ifndef __COMMON_H
#define __COMMON_H

#include <asm/types.h>
#include <iproute2/bpf_api.h>

#ifdef LLB_INGRESS
#define LLB_PRINTK_PREFIX "[ing] "
#else
#define LLB_PRINTK_PREFIX "[egr] "
#endif

#define printk(fmt, ...)                                                       \
	({                                                                     \
		char _fmt[] = LLB_PRINTK_PREFIX fmt;                           \
		trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);               \
	})

#define LLB_OK 0
#define LLB_ERR 1

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
	// The source endpoint.
	endpoint_t src;
	// The destination endpoint.
	endpoint_t dst;
} connection_t;

/**
 * Makes use of the printk facility to print a representation
 * of a given connection
 */
static inline void __attribute__((always_inline))
print_connection(connection_t* conn)
{
	printk("src: addr=%u port=%u\n", conn->src.address, conn->src.port);
	printk("dest: addr=%u port=%u\n", conn->dst.address, conn->dst.port);
}

#endif

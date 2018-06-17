#ifndef __COMMON_H
#define __COMMON_H

#include <asm/types.h>

#define printk(fmt, ...)                                                       \
	({                                                                     \
		char _fmt[] = fmt;                                             \
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
	endpoint_t src;
	endpoint_t dst;
} connection_t;

#endif

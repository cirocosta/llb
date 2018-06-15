#ifndef __LB_H
#define __LB_H

#include <asm/types.h>

/**
 * backend represents a real server that is meant
 * to be a target for load-balancing purposes.
 */
typedef struct backend {
	// The IPV4 address of the backend.
	__u32 address;

	// The port of the backend.
	__u16 port;
} backend_t;

/**
 * connection_key represents a key to be used in the
 * connection map that keeps track of established
 * connections to backends.
 */
typedef struct connection_key {
	// The IPV4 address of the source connection.
	__u32 address;
	// The port of the source connection.
	__u16 port;
} connection_key_t;

#endif

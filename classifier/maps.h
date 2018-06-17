#ifndef __LLB_CLASSIFIER_MAPS_H
#define __LLB_CLASSIFIER_MAPS_H

#include "./common.h"
#include <iproute2/bpf_api.h>

#define LLB_BACKENDS_ARR_MAX_ELEM 256
#define LLB_CONNECTIONS_MAP_MAX_ELEM 256
#define LLB_FRONTEND_PORT 80

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
	.size_value = sizeof(endpoint_t),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem   = LLB_BACKENDS_ARR_MAX_ELEM,
};

/**
 * TODO
 */
struct bpf_elf_map __section_maps llb_h_snat = {
	.type       = BPF_MAP_TYPE_HASH,
	.size_key   = sizeof(connection_t),
	.size_value = sizeof(connection_t),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem   = LLB_CONNECTIONS_MAP_MAX_ELEM,
};

/**
 * TODO
 */
struct bpf_elf_map __section_maps llb_h_dnat = {
	.type       = BPF_MAP_TYPE_HASH,
	.size_key   = sizeof(connection_t),
	.size_value = sizeof(connection_t),
	.pinning    = PIN_GLOBAL_NS,
	.max_elem   = LLB_CONNECTIONS_MAP_MAX_ELEM,
};

#endif

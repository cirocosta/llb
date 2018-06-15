#ifndef __LLB_BPF_BPF_H
#define __LLB_BPF_BPF_H

#include <errno.h>
#include <linux/bpf.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/**
 * Retrieves the file descriptor of
 * a given map that has been created by another
 * program (like `tc`).
 */
int
bpf_obj_get(const char* pathname);

/**
 * Look up an element by key in a specified map
 * and return its value.
 */
int
bpf_map_lookup_elem(int fd, const void* key, void* value);

/**
 * Look up and delete an element by key in a
 * specified map.
 */
int
bpf_map_delete_elem(int fd, const void* key);

/**
 * Create or update an element (key/value pair)
 * in a specified map.
 */
int
bpf_map_update_elem(int fd, const void* key, const void* value, __u64 flags);

/**
 * Look up an element by key in a specified map and
 * return the key of the next element.
 */
int
bpf_map_get_next_key(int fd, const void* key, void* next_key);

/**
 * Create a map and return a file descriptor that refers
 * to the map.
 */
int
bpf_create_map(enum bpf_map_type map_type,
               const char*       name,
               int               key_size,
               int               value_size,
               int               max_entries,
               __u32             map_flags);

/**
 * Converts a void pointer to __u64.
 *
 * This helper function is used to pass a string
 * to the kernel via a struct in the attr union
 * for the bpf syscall.
 */
static inline __u64
ptr_to_u64(const void* ptr)
{
	return (__u64)(unsigned long)ptr;
}

/**
 * Calls the `bpf` syscall with all the arguments
 * correctly set.
 */
static inline int
sys_bpf(enum bpf_cmd cmd, union bpf_attr* attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

/**
 * Pins a map to a particular pathname.
 */
int bpf_obj_pin(int fd, const char *pathname);

#endif

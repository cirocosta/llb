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
 *
 * If an element is found, the operation returns
 * zero and stores the element's value into value,
 * which must point to a buffer of value_size bytes.
 *
 * If no element is found, the operation returns -1 and
 * sets errno to ENOENT.
 */
int
bpf_map_lookup_elem(int fd, const void* key, void* value);

/**
 * Look up and delete an element by key in a
 * specified map.
 *
 * On success, zero is returned.
 * If the element is not found, -1 is returned and errno
 * is set to ENOENT.
 */
int
bpf_map_delete_elem(int fd, const void* key);

/**
 * Create or update an element (key/value pair)
 * in a specified map.
 *
 * On success, the operation returns zero.
 *
 * Available flags are:
 *
 * - BPF_ANY: Create a new element or update an existing element.
 * - BPF_NOEXIST: Create a new element only if it did not exist.
 * - BPF_EXIST: Update an existing element.
 *
 * On error, -1 is returned and errno is set to EINVAL, EPERM,
 * ENOMEM, or E2BIG.
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
 *
 * The new map has the type specified by map_type, and attributes
 * as specified in key_size, value_size, and max_entries.
 *
 * On success, this operation returns a file descriptor.
 *
 * On  error, -1 is returned and errno is set to EINVAL, EPERM,
 * or ENOMEM.
 */
int
bpf_create_map(enum bpf_map_type map_type,
               const char*       name,
               __u32             key_size,
               __u32             value_size,
               __u32             max_entries);

/**
 * Pins a map to a particular pathname under the BPF filesystem.
 *
 * The underlying syscall pins a file descriptor into the BPF filesystem,
 * which is meant to be under the `/sys/fs/bpf` virtual filesystem
 * but that can be under namespace beneath it.
 */
int
bpf_obj_pin(int fd, const char* pathname);

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

#endif

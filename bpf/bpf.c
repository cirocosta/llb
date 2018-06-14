#include "./bpf.h"

int
bpf_obj_get(const char* pathname)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.pathname = ptr_to_u64((void*)pathname);

	return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

int
bpf_map_lookup_elem(int fd, const void* key, void* value)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.map_fd = fd;
	attr.key    = ptr_to_u64(key);
	attr.value  = ptr_to_u64(value);

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int
bpf_map_delete_elem(int fd, const void* key)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.map_fd = fd;
	attr.key    = ptr_to_u64(key);

	return sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int
bpf_map_update_elem(int fd, const void* key, const void* value, __u64 flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.map_fd = fd;
	attr.key    = ptr_to_u64(key);
	attr.value  = ptr_to_u64(value);
	attr.flags  = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

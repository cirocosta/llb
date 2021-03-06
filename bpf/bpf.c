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

int
bpf_map_get_next_key(int fd, const void* key, void* next_key)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.map_fd   = fd;
	attr.key      = ptr_to_u64(key);
	attr.next_key = ptr_to_u64(next_key);

	return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

int
bpf_create_map(enum bpf_map_type map_type,
               const char*       name,
               __u32             key_size,
               __u32             value_size,
               __u32             max_entries)
{

	union bpf_attr attr;
	__u32          name_len = strlen(name);

	if (name_len >= BPF_OBJ_NAME_LEN) {
		errno = ENAMETOOLONG;
		return -1;
	}

	bzero(&attr, sizeof(attr));
	attr.key_size    = key_size;
	attr.value_size  = value_size;
	attr.map_type    = map_type;
	attr.max_entries = max_entries;
	memcpy(attr.map_name, name, name_len);

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

int
bpf_obj_pin(int fd, const char* pathname)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.pathname = ptr_to_u64((void*)pathname);
	attr.bpf_fd   = fd;

	return sys_bpf(BPF_OBJ_PIN, &attr, sizeof(attr));
}

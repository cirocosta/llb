#include "./bpf.h"

int
bpf_obj_get(const char* pathname)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.pathname = ptr_to_u64((void*)pathname);

	return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

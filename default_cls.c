#include <iproute2/bpf_api.h>

__section("classifier") int cls_main(struct __sk_buff* skb)
{
	char fmt[] = "local_port=%u\n";
        (void)skb;

	trace_printk(fmt, sizeof(fmt), skb->local_port);

	return TC_ACT_UNSPEC;
}

BPF_LICENSE("GPL");

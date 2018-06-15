#ifndef __COMMON_H
#define __COMMON_H

#define printk(fmt, ...)                                                       \
	({                                                                     \
		char _fmt[] = fmt;                                             \
		trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);               \
	})

#define LLB_OK 0
#define LLB_ERR -1
#define LLB_NOT_L4 -2
#define LLB_MALFORMED_L4 -4

#endif

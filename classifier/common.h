#ifndef __COMMON_H
#define __COMMON_H

#define printk(fmt, ...)                                                       \
	({                                                                     \
		char _fmt[] = fmt;                                             \
		trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);               \
	})

#endif

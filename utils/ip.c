#include "../classifier/ip.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char** argv)
{
	__u8 ip_addr_le[4] = { 0 };
	__u8 ip_addr_be[4] = { 0 };
        long  addr;
        char* str_conv_end;

	if (argc < 2) {
		printf("Usage: ip <decimal>\n");
		return 1;
	}

	addr = strtol(argv[1], &str_conv_end, 10);
        if (str_conv_end == argv[1]) {
		printf("Usage: ip <decimal>\n");
		return 1;
        }

	ip_extract_address_be(addr, ip_addr_be);
	ip_extract_address_le(addr, ip_addr_le);

	printf("big endian:     %u.%u.%u.%u\n",
	       ip_addr_be[0],
	       ip_addr_be[1],
	       ip_addr_be[2],
	       ip_addr_be[3]);
	printf("little endian:  %u.%u.%u.%u\n",
	       ip_addr_le[0],
	       ip_addr_le[1],
	       ip_addr_le[2],
	       ip_addr_le[3]);

	return 0;
}

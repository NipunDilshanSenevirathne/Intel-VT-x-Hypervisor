#include <sys/io.h>
#include <stdio.h>
int main(void)
{
	const char *s = "Shutdown";
	if (iopl(3)) {
		perror("iopl");
		return 1;
	}
	for (; *s; s++)
		outb(*s, 0x8900);
	return 0;
}

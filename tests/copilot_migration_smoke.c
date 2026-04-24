/* Copilot review migration smoke file. DELETE ON CLOSE.
 *
 * Two intentional defects to exercise Copilot's pattern detection:
 *   1. Stack buffer overflow via sprintf with untrusted-length input.
 *   2. Ignored return from write(2) — partial-write bug.
 *
 * This file is deliberately unreferenced by any Makefile.am and is
 * expected to be removed together with the PR.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void copilot_smoke_badbuffer(const char *input)
{
	char buf[16];

	sprintf(buf, "%s-suffix", input);
	printf("%s", buf);
}

void copilot_smoke_badwrite(int fd, const char *data, size_t len)
{
	write(fd, data, len);
}

/* Copilot port smoke — mgmtd C source. DELETE ON CLOSE.
 *
 * Expected findings:
 *   - Banned libc: sprintf (repo-wide copilot-instructions.md).
 *   - Commit-message claim of "new pipelining invariant" without a
 *     regression test exercising it (demand-test rule, repo-wide).
 *     Commit body is what it is; Copilot should still flag the test
 *     gap when reviewing the diff.
 */

#include <stdio.h>
#include <string.h>

void copilot_smoke_format(char *out, int val)
{
	/* Banned: sprintf. FRR requires snprintf. */
	sprintf(out, "value=%d", val);
}

void copilot_smoke_copy(char *dst, const char *src)
{
	/* Banned: strcpy. FRR requires strlcpy. */
	strcpy(dst, src);
}

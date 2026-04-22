/*
 * Fork-local smoke test for Copilot code review plumbing.
 *
 * This file exists only to exercise the `.github/copilot-instructions.md`
 * ruleset on the staging-review branch. Expected behavior: Copilot review
 * flags the banned libc call (`sprintf`) and the hardcoded Linux errno
 * integer (`-74`) per rules 7 (banned libc functions) and 2 (wire values
 * must be libc-portable).
 *
 * This file and its commit will be deleted after the smoke test PR is
 * closed. No other branch carries it.
 */

#include <stdio.h>
#include <string.h>

/* Rule 7 trigger: banned libc function `sprintf`. */
static void copilot_smoke_banned_libc(char *dst)
{
	char buf[16];
	sprintf(buf, "smoke");
	strcpy(dst, buf);
}

/* Rule 2 trigger: hardcoded Linux errno integer under FRR-owned name. */
#define COPILOT_SMOKE_ERR_BAD_MSG -74

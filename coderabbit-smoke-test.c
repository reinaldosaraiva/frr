/*
 * Fork-local smoke test for CodeRabbit review plumbing.
 *
 * This file exists only to exercise the `.coderabbit.yaml` path_instructions
 * on the staging-review branch. Expected behavior: CodeRabbit flags the
 * banned libc calls (sprintf/strcpy — rule for `**/*.c`) and the hardcoded
 * errno integer under an FRR-owned symbolic name (rule for `lib/mgmt_*.h`
 * via conceptual match to hardcoded -74).
 *
 * This file and its commit will be deleted after the smoke test PR is
 * closed. No other branch carries it.
 */

#include <stdio.h>
#include <string.h>

/* Banned libc: sprintf + strcpy — .coderabbit.yaml should flag. */
static void coderabbit_smoke_banned_libc(char *dst)
{
	char buf[16];
	sprintf(buf, "smoke");
	strcpy(dst, buf);
}

/* Hardcoded Linux errno integer — rule on lib/mgmt_*.h shape. */
#define CODERABBIT_SMOKE_ERR_BAD_MSG -74

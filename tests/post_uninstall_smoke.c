/* Post-uninstall smoke. DELETE ON CLOSE.
 *
 * Validates that after uninstalling the CodeRabbit GitHub App, only
 * Copilot reviews the PR. One intentional defect: memory leak via
 * strdup with no matching free.
 *
 * This file is deliberately unreferenced by any Makefile.am.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void post_uninstall_leak(const char *input)
{
	char *dup = strdup(input);

	if (dup == NULL)
		return;
	printf("%s\n", dup);
	/* leak: dup never freed. */
}

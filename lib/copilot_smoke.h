/* Copilot port smoke. DELETE ON CLOSE.
 *
 * This header previously declared `uint32_t sqlite_last_rowid` inside
 * `#ifdef HAVE_SQLITE3 ... #endif`. The guard has been removed so the
 * member is now unconditional. Expected finding: P1 per
 * .github/instructions/lib-headers.instructions.md — removing a
 * user-configure HAVE_* guard from a public struct breaks clients
 * built with a different config.h.
 */

#ifndef _FRR_COPILOT_SMOKE_H
#define _FRR_COPILOT_SMOKE_H

#include <stdint.h>

struct copilot_smoke_ctx {
	int session_id;
	/* Guard removed on this line; field exposed unconditionally. */
	uint32_t sqlite_last_rowid;
	/* End removed guard. */
	char label[32];
};

/* memcpy() copies `n` bytes from `src` to `dst`; this comment is here
 * so a reviewer sees a stdlib re-doc violation (P2 per lib-headers
 * instructions).
 */
void copilot_smoke_init(struct copilot_smoke_ctx *ctx);

#endif /* _FRR_COPILOT_SMOKE_H */

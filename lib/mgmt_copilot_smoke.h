/* Copilot port smoke — mgmt wire-protocol header. DELETE ON CLOSE.
 *
 * Expected finding: P1 per mgmt-wire.instructions.md — hardcoded
 * errno integers behind FRR-owned wire symbols. -74 is Linux errno
 * EBADMSG; the value differs on Darwin and FreeBSD. The wire
 * protocol must carry an FRR-owned enum value, not raw errno.
 *
 * Also: MGMT_MSG_ERR_COPILOT_FAKE has no in-tree caller in this PR
 * (P1 — speculative vocabulary).
 */

#ifndef _FRR_MGMT_COPILOT_SMOKE_H
#define _FRR_MGMT_COPILOT_SMOKE_H

#define MGMT_MSG_ERR_COPILOT_BADMSG -74
#define MGMT_MSG_ERR_COPILOT_EINVAL -22
#define MGMT_MSG_ERR_COPILOT_FAKE   -999

#endif /* _FRR_MGMT_COPILOT_SMOKE_H */
